-- ============================================================
-- Bisaya COD Community — D1 Schema
-- Run with: wrangler d1 execute <DB_NAME> --file=./schema.sql
-- ============================================================

DROP TABLE IF EXISTS applications;
DROP TABLE IF EXISTS loadout_votes;
DROP TABLE IF EXISTS loadouts;
DROP TABLE IF EXISTS scrim_rsvps;
DROP TABLE IF EXISTS scrims;
DROP TABLE IF EXISTS players;

-- ---------------------------------------------------------------
-- players: roster + leaderboard source of truth
-- ---------------------------------------------------------------
CREATE TABLE players (
  id            INTEGER PRIMARY KEY AUTOINCREMENT,
  ign           TEXT NOT NULL UNIQUE,
  discord       TEXT,
  role          TEXT DEFAULT 'Objective',   -- Slayer / Anchor / Objective / Support
  kd            REAL DEFAULT 0.0,
  wins          INTEGER DEFAULT 0,
  losses        INTEGER DEFAULT 0,
  member_since  TEXT DEFAULT (datetime('now')),
  is_active     INTEGER DEFAULT 1
);
CREATE INDEX idx_players_kd ON players(kd DESC);

-- ---------------------------------------------------------------
-- scrims: lobby postings
-- ---------------------------------------------------------------
CREATE TABLE scrims (
  id            INTEGER PRIMARY KEY AUTOINCREMENT,
  title         TEXT NOT NULL,
  mode          TEXT NOT NULL,              -- e.g. "SnD 5v5"
  map_pool      TEXT,
  slots         INTEGER NOT NULL DEFAULT 10,
  host_discord  TEXT,
  starts_at     TEXT,
  created_at    TEXT DEFAULT (datetime('now'))
);

CREATE TABLE scrim_rsvps (
  id            INTEGER PRIMARY KEY AUTOINCREMENT,
  scrim_id      INTEGER NOT NULL REFERENCES scrims(id) ON DELETE CASCADE,
  ign           TEXT NOT NULL,
  created_at    TEXT DEFAULT (datetime('now')),
  UNIQUE(scrim_id, ign)
);

-- ---------------------------------------------------------------
-- loadouts: community gunsmith builds
-- ---------------------------------------------------------------
CREATE TABLE loadouts (
  id            INTEGER PRIMARY KEY AUTOINCREMENT,
  weapon        TEXT NOT NULL,
  build_name    TEXT NOT NULL,
  share_code    TEXT NOT NULL,
  attachments   TEXT NOT NULL,              -- comma-separated summary
  meta_verified INTEGER DEFAULT 0,
  submitted_by  TEXT,
  created_at    TEXT DEFAULT (datetime('now'))
);

CREATE TABLE loadout_votes (
  id            INTEGER PRIMARY KEY AUTOINCREMENT,
  loadout_id    INTEGER NOT NULL REFERENCES loadouts(id) ON DELETE CASCADE,
  voter_key     TEXT NOT NULL,              -- hashed IP or session id — one vote per source
  created_at    TEXT DEFAULT (datetime('now')),
  UNIQUE(loadout_id, voter_key)
);

-- ---------------------------------------------------------------
-- applications: clan sign-ups from the modal form
-- ---------------------------------------------------------------
CREATE TABLE applications (
  id            INTEGER PRIMARY KEY AUTOINCREMENT,
  ign           TEXT NOT NULL,
  discord       TEXT NOT NULL,
  device        TEXT,
  uid           TEXT NOT NULL,
  status        TEXT DEFAULT 'pending',     -- pending / accepted / rejected
  created_at    TEXT DEFAULT (datetime('now'))
);

-- ---------------------------------------------------------------
-- seed data (safe to delete once real data comes in)
-- ---------------------------------------------------------------
INSERT INTO players (ign, role, kd, wins, losses) VALUES
  ('Slayer_Apex', 'Slayer', 3.12, 88, 21),
  ('Anchor_Pro', 'Anchor', 2.85, 74, 30),
  ('Bantay_Gwapo', 'Objective', 2.41, 65, 40),
  ('Kalog_Sniper', 'Anchor', 2.20, 51, 38);

INSERT INTO scrims (title, mode, map_pool, slots, host_discord) VALUES
  ('Community Custom Lobby', 'SnD 5v5', 'Raid, Summit, Standoff', 10, 'host#0001'),
  ('Legendary Push Scrim', 'Ranked 4v4', 'Nuketown, Crash', 8, 'host#0002'),
  ('Sundayscrim Warm-up', 'Multi-team', 'All maps, host''s choice', 10, 'host#0003');

INSERT INTO loadouts (weapon, build_name, share_code, attachments, meta_verified) VALUES
  ('BP50', 'Aggressive Build', 'BP50-88329', 'Monolithic Suppressor, No Stock, OWC Laser, 60 Rnd Mag', 1),
  ('Man-O-War', 'Anchor Build', 'MOW-41207', 'OWC Marksman, Fabric Grip, 6.7" CQB Pro, Tac Laser', 1),
  ('Fennec 45', 'Rush Build', 'FEN-90015', 'Speed Tape, Steady Grip, 45 Rnd Fast Mag, No Stock', 0),
  ('DL Q33', 'One-Shot Build', 'DLQ-77341', 'OWC Marksman, 26.8" Sniper Barrel, Steady Aim Sniper Set', 0);
