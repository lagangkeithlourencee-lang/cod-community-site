/**
 * Bisaya COD Community — API Worker
 *
 * Bindings required:
 *   DB                  -> D1 database (schema.sql + migration_admin_and_announcements.sql applied)
 *   TURNSTILE_SECRET    -> Turnstile secret key (Worker secret)
 *   ADMIN_SETUP_SECRET  -> long random string, used once to create your first admin account (Worker secret)
 *
 * NOTE: ADMIN_KEY / X-Admin-Key is retired. Admin routes now require
 * a Bearer session token obtained from POST /api/admin/login.
 *
 * Public routes:
 *   GET  /api/leaderboard
 *   GET  /api/scrims
 *   POST /api/scrims/:id/rsvp        { ign }
 *   GET  /api/loadouts
 *   POST /api/loadouts/:id/vote      { }
 *   GET  /api/announcements
 *   POST /api/apply                  { name, discord, device, uid, token }
 *
 * Admin auth:
 *   POST /api/admin/setup            { username, password, setupSecret }   (one-time)
 *   POST /api/admin/login            { username, password }
 *   POST /api/admin/logout
 *
 * Admin data (all require Authorization: Bearer <token>):
 *   GET    /api/admin/applications
 *   POST   /api/admin/applications/:id/status   { status }
 *
 *   GET    /api/admin/players
 *   POST   /api/admin/players                   { ign, kd, role, wins, losses, is_active }
 *   PUT    /api/admin/players/:id                (any subset of the above)
 *   DELETE /api/admin/players/:id
 *
 *   GET    /api/admin/scrims
 *   POST   /api/admin/scrims                    { title, mode, map_pool, slots }
 *   PUT    /api/admin/scrims/:id
 *   DELETE /api/admin/scrims/:id
 *
 *   GET    /api/admin/loadouts
 *   POST   /api/admin/loadouts                  { weapon, build_name, share_code, attachments, meta_verified }
 *   PUT    /api/admin/loadouts/:id
 *   DELETE /api/admin/loadouts/:id
 *
 *   GET    /api/admin/announcements
 *   POST   /api/admin/announcements             { message, active }
 *   PUT    /api/admin/announcements/:id
 *   DELETE /api/admin/announcements/:id
 *
 *   GET    /api/admin/audit-log
 */

const ALLOWED_ORIGIN = "https://lagangkeithlourencee-lang.github.io/cod-community-site/";

function cors(resp) {
  resp.headers.set("Access-Control-Allow-Origin", ALLOWED_ORIGIN);
  resp.headers.set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS");
  resp.headers.set("Access-Control-Allow-Headers", "Content-Type, Authorization");
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

/* ---------------- Admin auth helpers ---------------- */

function bufToHex(buf) {
  return [...new Uint8Array(buf)].map(b => b.toString(16).padStart(2, "0")).join("");
}
function hexToBuf(hex) {
  const bytes = new Uint8Array(hex.length / 2);
  for (let i = 0; i < hex.length; i += 2) bytes[i / 2] = parseInt(hex.substr(i, 2), 16);
  return bytes.buffer;
}
function randomHex(byteLen) {
  const arr = new Uint8Array(byteLen);
  crypto.getRandomValues(arr);
  return bufToHex(arr.buffer);
}
async function hashPassword(password, saltHex) {
  const enc = new TextEncoder();
  const keyMaterial = await crypto.subtle.importKey("raw", enc.encode(password), "PBKDF2", false, ["deriveBits"]);
  const bits = await crypto.subtle.deriveBits(
    { name: "PBKDF2", salt: hexToBuf(saltHex), iterations: 100000, hash: "SHA-256" },
    keyMaterial,
    256
  );
  return bufToHex(bits);
}
async function verifyPassword(password, saltHex, expectedHashHex) {
  const actual = await hashPassword(password, saltHex);
  if (actual.length !== expectedHashHex.length) return false;
  let diff = 0;
  for (let i = 0; i < actual.length; i++) diff |= actual.charCodeAt(i) ^ expectedHashHex.charCodeAt(i);
  return diff === 0;
}

async function logAudit(env, { adminId, adminUsername, action, target, detail, ip }) {
  await env.DB.prepare(
    `INSERT INTO admin_audit_log (admin_id, admin_username, action, target, detail, ip)
     VALUES (?, ?, ?, ?, ?, ?)`
  ).bind(adminId ?? null, adminUsername ?? null, action, target ?? null, detail ?? null, ip ?? null).run();
}

async function requireAdmin(request, env) {
  const auth = request.headers.get("Authorization") || "";
  const token = auth.startsWith("Bearer ") ? auth.slice(7).trim() : null;
  if (!token) return null;

  const row = await env.DB.prepare(
    `SELECT s.token, s.admin_id, s.expires_at, u.username
     FROM admin_sessions s JOIN admin_users u ON u.id = s.admin_id
     WHERE s.token = ?`
  ).bind(token).first();

  if (!row) return null;
  if (new Date(row.expires_at) < new Date()) {
    await env.DB.prepare(`DELETE FROM admin_sessions WHERE token = ?`).bind(token).run();
    return null;
  }

  env.DB.prepare(`UPDATE admin_sessions SET last_used_at = datetime('now') WHERE token = ?`)
    .bind(token).run().catch(() => {});

  return { adminId: row.admin_id, username: row.username, token };
}

function buildUpdate(body, allowedCols) {
  const sets = [];
  const values = [];
  for (const col of allowedCols) {
    if (Object.prototype.hasOwnProperty.call(body, col)) {
      sets.push(`${col} = ?`);
      values.push(body[col]);
    }
  }
  if (!sets.length) return null;
  return { clause: sets.join(", "), values };
}

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    const ip = request.headers.get("CF-Connecting-IP") || "0.0.0.0";

    if (request.method === "OPTIONS") return cors(new Response(null, { status: 204 }));

    try {
      /* ===================== PUBLIC ROUTES ===================== */

      if (url.pathname === "/api/leaderboard" && request.method === "GET") {
        const { results } = await env.DB.prepare(
          `SELECT ign, kd, role, wins, losses FROM players WHERE is_active = 1 ORDER BY kd DESC LIMIT 50`
        ).all();
        return json({ players: results });
      }

      if (url.pathname === "/api/scrims" && request.method === "GET") {
        const { results } = await env.DB.prepare(
          `SELECT s.id, s.title, s.mode, s.map_pool, s.slots,
                  (SELECT COUNT(*) FROM scrim_rsvps r WHERE r.scrim_id = s.id) AS filled
           FROM scrims s ORDER BY s.created_at DESC LIMIT 20`
        ).all();
        return json({ scrims: results });
      }

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

      if (url.pathname === "/api/loadouts" && request.method === "GET") {
        const { results } = await env.DB.prepare(
          `SELECT l.id, l.weapon, l.build_name, l.share_code, l.attachments, l.meta_verified,
                  (SELECT COUNT(*) FROM loadout_votes v WHERE v.loadout_id = l.id) AS votes
           FROM loadouts l ORDER BY votes DESC LIMIT 20`
        ).all();
        return json({ loadouts: results });
      }

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

      if (url.pathname === "/api/announcements" && request.method === "GET") {
        const { results } = await env.DB.prepare(
          `SELECT id, message, created_at FROM announcements WHERE active = 1 ORDER BY created_at DESC LIMIT 5`
        ).all();
        return json({ announcements: results });
      }

      if (url.pathname === "/api/apply" && request.method === "POST") {
        const { name, discord, device, uid, token } = await request.json();

        if (!name || !discord || !uid) return json({ error: "Missing required fields" }, 400);
        if (!/^[0-9]{6,15}$/.test(uid)) return json({ error: "Invalid UID format" }, 400);

        const verified = await verifyTurnstile(token, ip, env.TURNSTILE_SECRET);
        if (!verified) return json({ error: "Verification failed. Please retry the check." }, 403);

        const recent = await env.DB.prepare(
          `SELECT COUNT(*) as count FROM applications WHERE uid = ? AND created_at > datetime('now', '-1 day')`
        ).bind(uid).first();
        if (recent.count >= 3) return json({ error: "Too many applications from this UID today" }, 429);

        await env.DB.prepare(
          `INSERT INTO applications (ign, discord, device, uid) VALUES (?, ?, ?, ?)`
        ).bind(name, discord, device || "Unknown", uid).run();

        return json({ ok: true });
      }

      /* ===================== ADMIN AUTH ===================== */

      if (url.pathname === "/api/admin/setup" && request.method === "POST") {
        const { username, password, setupSecret } = await request.json();

        if (!env.ADMIN_SETUP_SECRET || setupSecret !== env.ADMIN_SETUP_SECRET) {
          return json({ error: "Forbidden" }, 403);
        }
        const { count } = await env.DB.prepare(`SELECT COUNT(*) as count FROM admin_users`).first();
        if (count > 0) return json({ error: "Setup already completed" }, 403);
        if (!username || !password || password.length < 10) {
          return json({ error: "Username and a password of at least 10 characters are required" }, 400);
        }

        const salt = randomHex(16);
        const hash = await hashPassword(password, salt);
        await env.DB.prepare(
          `INSERT INTO admin_users (username, password_hash, salt) VALUES (?, ?, ?)`
        ).bind(username, hash, salt).run();

        return json({ ok: true });
      }

      if (url.pathname === "/api/admin/login" && request.method === "POST") {
        const { count: recentAttempts } = await env.DB.prepare(
          `SELECT COUNT(*) as count FROM admin_login_attempts
           WHERE ip = ? AND attempted_at > datetime('now', '-15 minutes')`
        ).bind(ip).first();

        if (recentAttempts >= 8) return json({ error: "Too many login attempts. Try again later." }, 429);

        const { username, password } = await request.json();
        const user = await env.DB.prepare(`SELECT * FROM admin_users WHERE username = ?`)
          .bind(username || "").first();

        const ok = user ? await verifyPassword(password || "", user.salt, user.password_hash) : false;

        await env.DB.prepare(`INSERT INTO admin_login_attempts (ip, success) VALUES (?, ?)`)
          .bind(ip, ok ? 1 : 0).run();

        if (!ok) return json({ error: "Invalid credentials" }, 401);

        const token = randomHex(32);
        const expiresAt = new Date(Date.now() + 12 * 60 * 60 * 1000).toISOString();

        await env.DB.prepare(`INSERT INTO admin_sessions (token, admin_id, expires_at) VALUES (?, ?, ?)`)
          .bind(token, user.id, expiresAt).run();

        await logAudit(env, { adminId: user.id, adminUsername: user.username, action: "login", ip });

        return json({ token, expiresAt, username: user.username });
      }

      if (url.pathname === "/api/admin/logout" && request.method === "POST") {
        const session = await requireAdmin(request, env);
        if (!session) return json({ error: "Unauthorized" }, 401);

        await env.DB.prepare(`DELETE FROM admin_sessions WHERE token = ?`).bind(session.token).run();
        await logAudit(env, { adminId: session.adminId, adminUsername: session.username, action: "logout", ip });

        return json({ ok: true });
      }

      /* ===================== ADMIN DATA (session required) ===================== */

      if (url.pathname.startsWith("/api/admin/")) {
        const session = await requireAdmin(request, env);
        if (!session) return json({ error: "Unauthorized" }, 401);
        const who = { adminId: session.adminId, adminUsername: session.username, ip };

        // ---- Applications ----
        if (url.pathname === "/api/admin/applications" && request.method === "GET") {
          const { results } = await env.DB.prepare(
            `SELECT id, ign, discord, device, uid, status, created_at
             FROM applications ORDER BY created_at DESC LIMIT 200`
          ).all();
          return json({ applications: results });
        }

        const statusMatch = url.pathname.match(/^\/api\/admin\/applications\/(\d+)\/status$/);
        if (statusMatch && request.method === "POST") {
          const appId = Number(statusMatch[1]);
          const { status } = await request.json();
          if (!["accepted", "rejected", "pending"].includes(status)) {
            return json({ error: "Invalid status" }, 400);
          }
          await env.DB.prepare(`UPDATE applications SET status = ? WHERE id = ?`).bind(status, appId).run();
          await logAudit(env, { ...who, action: "application_status_change", target: `application:${appId}`, detail: status });
          return json({ ok: true });
        }

        // ---- Players / Leaderboard ----
        if (url.pathname === "/api/admin/players" && request.method === "GET") {
          const { results } = await env.DB.prepare(`SELECT * FROM players ORDER BY kd DESC`).all();
          return json({ players: results });
        }
        if (url.pathname === "/api/admin/players" && request.method === "POST") {
          const b = await request.json();
          if (!b.ign) return json({ error: "ign is required" }, 400);
          const r = await env.DB.prepare(
            `INSERT INTO players (ign, kd, role, wins, losses, is_active) VALUES (?, ?, ?, ?, ?, ?)`
          ).bind(b.ign, b.kd ?? 0, b.role ?? null, b.wins ?? 0, b.losses ?? 0, b.is_active ?? 1).run();
          await logAudit(env, { ...who, action: "player_create", target: `player:${r.meta.last_row_id}`, detail: b.ign });
          return json({ ok: true, id: r.meta.last_row_id });
        }
        const playerMatch = url.pathname.match(/^\/api\/admin\/players\/(\d+)$/);
        if (playerMatch && request.method === "PUT") {
          const id = Number(playerMatch[1]);
          const b = await request.json();
          const upd = buildUpdate(b, ["ign", "kd", "role", "wins", "losses", "is_active"]);
          if (!upd) return json({ error: "No valid fields to update" }, 400);
          await env.DB.prepare(`UPDATE players SET ${upd.clause} WHERE id = ?`).bind(...upd.values, id).run();
          await logAudit(env, { ...who, action: "player_update", target: `player:${id}`, detail: JSON.stringify(b) });
          return json({ ok: true });
        }
        if (playerMatch && request.method === "DELETE") {
          const id = Number(playerMatch[1]);
          await env.DB.prepare(`DELETE FROM players WHERE id = ?`).bind(id).run();
          await logAudit(env, { ...who, action: "player_delete", target: `player:${id}` });
          return json({ ok: true });
        }

        // ---- Scrims ----
        if (url.pathname === "/api/admin/scrims" && request.method === "GET") {
          const { results } = await env.DB.prepare(
            `SELECT s.*, (SELECT COUNT(*) FROM scrim_rsvps r WHERE r.scrim_id = s.id) AS filled
             FROM scrims s ORDER BY s.created_at DESC`
          ).all();
          return json({ scrims: results });
        }
        if (url.pathname === "/api/admin/scrims" && request.method === "POST") {
          const b = await request.json();
          if (!b.title || !b.slots) return json({ error: "title and slots are required" }, 400);
          const r = await env.DB.prepare(
            `INSERT INTO scrims (title, mode, map_pool, slots) VALUES (?, ?, ?, ?)`
          ).bind(b.title, b.mode ?? null, b.map_pool ?? null, b.slots).run();
          await logAudit(env, { ...who, action: "scrim_create", target: `scrim:${r.meta.last_row_id}`, detail: b.title });
          return json({ ok: true, id: r.meta.last_row_id });
        }
        const scrimMatch = url.pathname.match(/^\/api\/admin\/scrims\/(\d+)$/);
        if (scrimMatch && request.method === "PUT") {
          const id = Number(scrimMatch[1]);
          const b = await request.json();
          const upd = buildUpdate(b, ["title", "mode", "map_pool", "slots"]);
          if (!upd) return json({ error: "No valid fields to update" }, 400);
          await env.DB.prepare(`UPDATE scrims SET ${upd.clause} WHERE id = ?`).bind(...upd.values, id).run();
          await logAudit(env, { ...who, action: "scrim_update", target: `scrim:${id}`, detail: JSON.stringify(b) });
          return json({ ok: true });
        }
        if (scrimMatch && request.method === "DELETE") {
          const id = Number(scrimMatch[1]);
          await env.DB.prepare(`DELETE FROM scrim_rsvps WHERE scrim_id = ?`).bind(id).run();
          await env.DB.prepare(`DELETE FROM scrims WHERE id = ?`).bind(id).run();
          await logAudit(env, { ...who, action: "scrim_delete", target: `scrim:${id}` });
          return json({ ok: true });
        }

        // ---- Loadouts ----
        if (url.pathname === "/api/admin/loadouts" && request.method === "GET") {
          const { results } = await env.DB.prepare(
            `SELECT l.*, (SELECT COUNT(*) FROM loadout_votes v WHERE v.loadout_id = l.id) AS votes
             FROM loadouts l ORDER BY l.id DESC`
          ).all();
          return json({ loadouts: results });
        }
        if (url.pathname === "/api/admin/loadouts" && request.method === "POST") {
          const b = await request.json();
          if (!b.weapon || !b.build_name) return json({ error: "weapon and build_name are required" }, 400);
          const r = await env.DB.prepare(
            `INSERT INTO loadouts (weapon, build_name, share_code, attachments, meta_verified)
             VALUES (?, ?, ?, ?, ?)`
          ).bind(b.weapon, b.build_name, b.share_code ?? null, b.attachments ?? null, b.meta_verified ?? 0).run();
          await logAudit(env, { ...who, action: "loadout_create", target: `loadout:${r.meta.last_row_id}`, detail: b.build_name });
          return json({ ok: true, id: r.meta.last_row_id });
        }
        const loadoutMatch = url.pathname.match(/^\/api\/admin\/loadouts\/(\d+)$/);
        if (loadoutMatch && request.method === "PUT") {
          const id = Number(loadoutMatch[1]);
          const b = await request.json();
          const upd = buildUpdate(b, ["weapon", "build_name", "share_code", "attachments", "meta_verified"]);
          if (!upd) return json({ error: "No valid fields to update" }, 400);
          await env.DB.prepare(`UPDATE loadouts SET ${upd.clause} WHERE id = ?`).bind(...upd.values, id).run();
          await logAudit(env, { ...who, action: "loadout_update", target: `loadout:${id}`, detail: JSON.stringify(b) });
          return json({ ok: true });
        }
        if (loadoutMatch && request.method === "DELETE") {
          const id = Number(loadoutMatch[1]);
          await env.DB.prepare(`DELETE FROM loadout_votes WHERE loadout_id = ?`).bind(id).run();
          await env.DB.prepare(`DELETE FROM loadouts WHERE id = ?`).bind(id).run();
          await logAudit(env, { ...who, action: "loadout_delete", target: `loadout:${id}` });
          return json({ ok: true });
        }

        // ---- Announcements ----
        if (url.pathname === "/api/admin/announcements" && request.method === "GET") {
          const { results } = await env.DB.prepare(`SELECT * FROM announcements ORDER BY created_at DESC`).all();
          return json({ announcements: results });
        }
        if (url.pathname === "/api/admin/announcements" && request.method === "POST") {
          const b = await request.json();
          if (!b.message) return json({ error: "message is required" }, 400);
          const r = await env.DB.prepare(
            `INSERT INTO announcements (message, active) VALUES (?, ?)`
          ).bind(b.message, b.active ?? 1).run();
          await logAudit(env, { ...who, action: "announcement_create", target: `announcement:${r.meta.last_row_id}` });
          return json({ ok: true, id: r.meta.last_row_id });
        }
        const annMatch = url.pathname.match(/^\/api\/admin\/announcements\/(\d+)$/);
        if (annMatch && request.method === "PUT") {
          const id = Number(annMatch[1]);
          const b = await request.json();
          const upd = buildUpdate(b, ["message", "active"]);
          if (!upd) return json({ error: "No valid fields to update" }, 400);
          await env.DB.prepare(
            `UPDATE announcements SET ${upd.clause}, updated_at = datetime('now') WHERE id = ?`
          ).bind(...upd.values, id).run();
          await logAudit(env, { ...who, action: "announcement_update", target: `announcement:${id}`, detail: JSON.stringify(b) });
          return json({ ok: true });
        }
        if (annMatch && request.method === "DELETE") {
          const id = Number(annMatch[1]);
          await env.DB.prepare(`DELETE FROM announcements WHERE id = ?`).bind(id).run();
          await logAudit(env, { ...who, action: "announcement_delete", target: `announcement:${id}` });
          return json({ ok: true });
        }

        // ---- Audit log ----
        if (url.pathname === "/api/admin/audit-log" && request.method === "GET") {
          const { results } = await env.DB.prepare(
            `SELECT * FROM admin_audit_log ORDER BY created_at DESC LIMIT 200`
          ).all();
          return json({ log: results });
        }

        return json({ error: "Not found" }, 404);
      }

      return json({ error: "Not found" }, 404);
    } catch (err) {
      return json({ error: "Server error", detail: String(err) }, 500);
    }
  },
};
