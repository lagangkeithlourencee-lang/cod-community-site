/**
 * Bisaya COD Community — API Worker
 * Bindings required (set in wrangler.toml or the dashboard):
 *   DB              -> D1 database bound with schema.sql applied
 *   TURNSTILE_SECRET -> your Turnstile secret key (Worker secret, not a var)
 *
 * Routes:
 *   GET  /api/leaderboard
 *   GET  /api/scrims
 *   POST /api/scrims/:id/rsvp        { ign }
 *   GET  /api/loadouts
 *   POST /api/loadouts/:id/vote      { }               (voter identified by IP hash)
 *   POST /api/apply                  { name, discord, device, uid, token }
 */

const ALLOWED_ORIGIN = "https://your-domain-here.com"; // <-- set this to your real domain

function cors(resp) {
  resp.headers.set("Access-Control-Allow-Origin", ALLOWED_ORIGIN);
  resp.headers.set("Access-Control-Allow-Methods", "GET, POST, OPTIONS");
  resp.headers.set("Access-Control-Allow-Headers", "Content-Type");
  return resp;
}

function json(data, status = 200) {
  return cors(new Response(JSON.stringify(data), {
    status,
    headers: { "Content-Type": "application/json" },
  }));
}

async function hashIp(ip, salt) {
  const enc = new TextEncoder().encode(ip + salt);
  const digest = await crypto.subtle.digest("SHA-256", enc);
  return [...new Uint8Array(digest)].map(b => b.toString(16).padStart(2, "0")).join("");
}

async function verifyTurnstile(token, ip, secret) {
  if (!token) return false;
  const body = new URLSearchParams({ secret, response: token, remoteip: ip });
  const res = await fetch("https://challenges.cloudflare.com/turnstile/v0/siteverify", {
    method: "POST",
    body,
  });
  const outcome = await res.json();
  return outcome.success === true;
}

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    const ip = request.headers.get("CF-Connecting-IP") || "0.0.0.0";

    if (request.method === "OPTIONS") return cors(new Response(null, { status: 204 }));

    try {
      // ---- GET /api/leaderboard ----
      if (url.pathname === "/api/leaderboard" && request.method === "GET") {
        const { results } = await env.DB.prepare(
          `SELECT ign, kd, role, wins, losses FROM players WHERE is_active = 1 ORDER BY kd DESC LIMIT 50`
        ).all();
        return json({ players: results });
      }

      // ---- GET /api/scrims ----
      if (url.pathname === "/api/scrims" && request.method === "GET") {
        const { results } = await env.DB.prepare(
          `SELECT s.id, s.title, s.mode, s.map_pool, s.slots,
                  (SELECT COUNT(*) FROM scrim_rsvps r WHERE r.scrim_id = s.id) AS filled
           FROM scrims s ORDER BY s.created_at DESC LIMIT 20`
        ).all();
        return json({ scrims: results });
      }

      // ---- POST /api/scrims/:id/rsvp ----
      const rsvpMatch = url.pathname.match(/^\/api\/scrims\/(\d+)\/rsvp$/);
      if (rsvpMatch && request.method === "POST") {
        const scrimId = Number(rsvpMatch[1]);
        const { ign } = await request.json();
        if (!ign || ign.length > 32) return json({ error: "Invalid IGN" }, 400);

        const scrim = await env.DB.prepare(`SELECT slots FROM scrims WHERE id = ?`).bind(scrimId).first();
        if (!scrim) return json({ error: "Scrim not found" }, 404);

        const { count } = await env.DB.prepare(
          `SELECT COUNT(*) as count FROM scrim_rsvps WHERE scrim_id = ?`
        ).bind(scrimId).first();
        if (count >= scrim.slots) return json({ error: "Lobby full" }, 409);

        await env.DB.prepare(
          `INSERT OR IGNORE INTO scrim_rsvps (scrim_id, ign) VALUES (?, ?)`
        ).bind(scrimId, ign).run();

        return json({ ok: true, filled: count + 1 });
      }

      // ---- GET /api/loadouts ----
      if (url.pathname === "/api/loadouts" && request.method === "GET") {
        const { results } = await env.DB.prepare(
          `SELECT l.id, l.weapon, l.build_name, l.share_code, l.attachments, l.meta_verified,
                  (SELECT COUNT(*) FROM loadout_votes v WHERE v.loadout_id = l.id) AS votes
           FROM loadouts l ORDER BY votes DESC LIMIT 20`
        ).all();
        return json({ loadouts: results });
      }

      // ---- POST /api/loadouts/:id/vote ----
      const voteMatch = url.pathname.match(/^\/api\/loadouts\/(\d+)\/vote$/);
      if (voteMatch && request.method === "POST") {
        const loadoutId = Number(voteMatch[1]);
        const voterKey = await hashIp(ip, "loadout-vote-salt");

        const existing = await env.DB.prepare(
          `SELECT id FROM loadout_votes WHERE loadout_id = ? AND voter_key = ?`
        ).bind(loadoutId, voterKey).first();

        if (existing) {
          await env.DB.prepare(`DELETE FROM loadout_votes WHERE id = ?`).bind(existing.id).run();
          return json({ ok: true, voted: false });
        } else {
          await env.DB.prepare(
            `INSERT INTO loadout_votes (loadout_id, voter_key) VALUES (?, ?)`
          ).bind(loadoutId, voterKey).run();
          return json({ ok: true, voted: true });
        }
      }

      // ---- POST /api/apply ----
      if (url.pathname === "/api/apply" && request.method === "POST") {
        const { name, discord, device, uid, token } = await request.json();

        if (!name || !discord || !uid) return json({ error: "Missing required fields" }, 400);
        if (!/^[0-9]{6,15}$/.test(uid)) return json({ error: "Invalid UID format" }, 400);

        const verified = await verifyTurnstile(token, ip, env.TURNSTILE_SECRET);
        if (!verified) return json({ error: "Verification failed. Please retry the check." }, 403);

        // basic per-IP rate limit: block a 4th application from the same IP in 24h
        const recent = await env.DB.prepare(
          `SELECT COUNT(*) as count FROM applications WHERE uid = ? AND created_at > datetime('now', '-1 day')`
        ).bind(uid).first();
        if (recent.count >= 3) return json({ error: "Too many applications from this UID today" }, 429);

        await env.DB.prepare(
          `INSERT INTO applications (ign, discord, device, uid) VALUES (?, ?, ?, ?)`
        ).bind(name, discord, device || "Unknown", uid).run();

        return json({ ok: true });
      }

      return json({ error: "Not found" }, 404);
    } catch (err) {
      return json({ error: "Server error", detail: String(err) }, 500);
    }
  },
};
