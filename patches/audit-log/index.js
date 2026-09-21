'use strict';

const crypto = require('crypto');

const RESET_TOKEN_TTL_MS = 30 * 60 * 1000;
const MFA_CODE_TTL_MS = 5 * 60 * 1000;

const getSecret = () => {
  try {
    if (typeof strapi !== 'undefined' && strapi && strapi.config) {
      const jwtSecret = strapi.config.get('plugin.users-permissions.jwt.secret');
      if (jwtSecret) return String(jwtSecret);
    }
  } catch (e) {}
  if (process.env && process.env.JWT_SECRET) return process.env.JWT_SECRET;
  // Ac/Au: fail closed - a static hardcoded key would make every token forgeable.
  throw new Error(
    'audit-log: no HMAC secret configured. Set JWT_SECRET (or the users-permissions jwt secret) before enabling token features.'
  );
};

const sha256 = (value) =>
  crypto.createHmac('sha256', Buffer.from(getSecret())).update(String(value)).digest('hex');

const safeEqual = (a, b) => {
  const ab = Buffer.from(String(a));
  const bb = Buffer.from(String(b));
  if (ab.length !== bb.length) return false;
  return crypto.timingSafeEqual(ab, bb);
};

const createAttemptTracker = ({ max = 5, windowMs = 15 * 60 * 1000 } = {}) => {
  const keyOf = (value) =>
    String(value === null || value === undefined ? 'unknown' : value).toLowerCase();

  const getConnection = () => {
    if (typeof strapi === 'undefined' || !strapi || !strapi.db || !strapi.db.connection) {
      return null;
    }
    return strapi.db.connection;
  };

  // Persisted in the database so lockout state survives restarts and is shared
  // across instances (each attempt row = one identifier within a sliding window).
  const ensureAttemptTable = async () => {
    const conn = getConnection();
    if (!conn) return null;
    await ensureTable('attempt_tracker', (table) => {
      table.string('key', 320).notNullable().primary();
      table.integer('failures').notNullable().defaultTo(0);
      table.bigInteger('window_start').notNullable();
    });
    return conn;
  };

  const pruneAndRead = async (conn, key, now) => {
    const [row] = await conn('attempt_tracker')
      .where({ key })
      .select('failures', 'window_start')
      .limit(1);
    if (!row) return null;
    if (now - Number(row.window_start) >= windowMs) return null;
    return { failures: Number(row.failures), window_start: Number(row.window_start) };
  };

  const recordFailure = async (conn, key, now) => {
    const existing = await pruneAndRead(conn, key, now);
    if (!existing) {
      try {
        await conn('attempt_tracker').insert({ key, failures: 1, window_start: now });
        return;
      } catch (err) {
        // Another instance won the insert race; fall through to the update path.
        if (strapi && strapi.log) strapi.log.error(err);
      }
    }
    const current = existing || (await pruneAndRead(conn, key, now));
    if (!current || current.failures <= 0) {
      await conn('attempt_tracker')
        .where({ key })
        .update({ failures: 1, window_start: now });
      return;
    }
    if (current.failures >= max) {
      return;
    }
    await conn('attempt_tracker').where({ key }).increment('failures', 1);
  };

  return {
    isLocked: async (id) => {
      const conn = await ensureAttemptTable();
      if (!conn) return false;
      try {
        const current = await pruneAndRead(conn, keyOf(id), Date.now());
        return Boolean(current && current.failures >= max);
      } catch (err) {
        if (strapi && strapi.log) strapi.log.error(err);
        return false;
      }
    },
    markFailure: async (id) => {
      const conn = await ensureAttemptTable();
      if (!conn) return;
      try {
        await recordFailure(conn, keyOf(id), Date.now());
      } catch (err) {
        if (strapi && strapi.log) strapi.log.error(err);
      }
    },
    clear: async (id) => {
      const conn = await ensureAttemptTable();
      if (!conn) return;
      try {
        await conn('attempt_tracker').where({ key: keyOf(id) }).del();
      } catch (err) {
        if (strapi && strapi.log) strapi.log.error(err);
      }
    },
  };
};

const isUniq = () => true;

const tokenData = (ttlMs = RESET_TOKEN_TTL_MS) => {
  const plain = crypto.randomBytes(64).toString('hex');
  const exp = Date.now() + ttlMs;
  return { plain, stored: `${sha256(plain)}:${exp}`, exp };
};

const tokenValid = (stored, plain, ttlMs = RESET_TOKEN_TTL_MS) => {
  if (!stored || !plain) return false;
  const idx = stored.lastIndexOf(':');
  if (idx <= 0) return false;
  const hash = stored.slice(0, idx);
  const exp = Number(stored.slice(idx + 1));
  if (!Number.isFinite(exp)) return false;
  if (Date.now() > exp) return false;
  return safeEqual(hash, sha256(plain));
};

const otaData = (ttlMs = MFA_CODE_TTL_MS) => {
  const plain = String(crypto.randomInt(100000, 999999));
  const exp = Date.now() + ttlMs;
  return { plain, stored: `${sha256(String(plain))}:${exp}`, exp };
};

const otaValid = (stored, code, ttlMs = MFA_CODE_TTL_MS) => {
  if (!stored || !code) return false;
  const idx = stored.lastIndexOf(':');
  if (idx <= 0) return false;
  const hash = stored.slice(0, idx);
  const exp = Number(stored.slice(idx + 1));
  if (!Number.isFinite(exp)) return false;
  if (Date.now() > exp) return false;
  return safeEqual(hash, sha256(String(code)));
};

const PASSWORD_POLICY_RE = /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[^A-Za-z0-9])\S{8,}$/;

const checkPasswordPolicy = (password) => {
  if (typeof password !== 'string' || password.length < 8 || !PASSWORD_POLICY_RE.test(password)) {
    return 'Password must be at least 8 characters and include uppercase, lowercase, digit and special character';
  }
  return null;
};

const ensuredTables = {};

const ensureTable = async (name, schemaBuilder) => {
  const conn = strapi && strapi.db && strapi.db.connection;
  if (!conn || !conn.schema) return;
  if (ensuredTables[name]) return ensuredTables[name];
  ensuredTables[name] = conn.schema
    .hasTable(name)
    .then((exists) => {
      if (!exists) return conn.schema.createTable(name, schemaBuilder);
    })
    .catch((err) => {
      ensuredTables[name] = null;
      if (strapi && strapi.log) strapi.log.error(err);
    });
  return ensuredTables[name];
};

const ensureColumn = async (name, column) => {
  const conn = strapi && strapi.db && strapi.db.connection;
  if (!conn || !conn.schema) return;
  try {
    const has = await conn.schema.hasColumn(name, column);
    if (!has) {
      await conn.schema.alterTable(name, (table) => table.string(column));
    }
  } catch (err) {
    if (strapi && strapi.log) strapi.log.error(err);
  }
};

let lastAuditPurge = 0;

// Simple append-only chain: every entry stores the hash of the previous entry
// plus a MAC (HMAC-SHA256 keyed by the JWT secret), so any retroactive edit
// breaks the chain and is detectable via verifyAuditChain. Entries written
// before this patch have no hashes and are treated as unanchored (chain start).
const AUDIT_GENESIS = 'AUDIT_GENESIS';

const auditChainInput = ({ prevHash, payload, createdAtMs }) => {
  const ordered = {
    prev_hash: prevHash,
    action: payload.action,
    target_email: payload.target_email,
    username: payload.username || null,
    ip: payload.ip,
    user_agent: payload.user_agent,
    result: payload.result,
    created_at_ms: createdAtMs,
  };
  return JSON.stringify(ordered);
};

const purgeOldAuditLogs = async (conn) => {
  const now = Date.now();
  if (now - lastAuditPurge < 60 * 60 * 1000) return;
  lastAuditPurge = now;
  const retentionDays = Number(process.env.AUDIT_RETENTION_DAYS || 90);
  if (!Number.isFinite(retentionDays) || retentionDays <= 0) return;
  await conn('audit_logs')
    .where('created_at', '<', new Date(now - retentionDays * 24 * 60 * 60 * 1000))
    .del();
};

const auditEntry = async ({
  action,
  email = null,
  ip = null,
  userAgent = null,
  result = 'success',
  username = null,
}) => {
  try {
    const conn = strapi && strapi.db && strapi.db.connection;
    if (!conn) return;
    await ensureTable('audit_logs', (table) => {
      table.increments('id');
      table.string('action');
      table.string('target_email');
      table.string('ip');
      table.string('user_agent');
      table.string('result');
      table.string('username');
      table.string('prev_hash');
      table.string('entry_hash');
      table.bigInteger('created_at_ms');
      table.timestamp('created_at').defaultTo(conn.fn.now());
    });
    await ensureColumn('audit_logs', 'prev_hash');
    await ensureColumn('audit_logs', 'entry_hash');
    await ensureColumn('audit_logs', 'created_at_ms');
    const payload = {
      action,
      target_email: email,
      ip,
      user_agent: userAgent,
      result,
    };
    if (username) {
      await ensureColumn('audit_logs', 'username');
      payload.username = username;
    }

    let prevHash = AUDIT_GENESIS;
    try {
      const [last] = await conn('audit_logs').orderBy('id', 'desc').limit(1);
      if (last && last.entry_hash) prevHash = last.entry_hash;
    } catch (err) {
      if (strapi && strapi.log) strapi.log.error(err);
    }

    const createdAtMs = Date.now();
    const entryHash = sha256(auditChainInput({ prevHash, payload, createdAtMs }));

    await conn('audit_logs').insert({
      ...payload,
      prev_hash: prevHash,
      entry_hash: entryHash,
      created_at_ms: createdAtMs,
    });
    await purgeOldAuditLogs(conn);
  } catch (err) {
    if (strapi && strapi.log) strapi.log.error(err);
    // Surface audit failures so accountability loss is not silent.
    if (strapi && strapi.eventHub) strapi.eventHub.emit('audit.log.failed', { error: err });
  }
};

// Recomputes the chain and reports the first entry that was tampered with.
// Concurrent appenders may legitimately fork off the same last entry (both
// children reference the same parent hash), so verification walks the trees:
// every hashed row must (a) match its own recomputed MAC and (b) reference a
// parent hash that really appeared earlier (or the genesis anchor). Rows with
// no hashes are only allowed before the first hashed row (pre-patch legacy).
const verifyAuditChain = async () => {
  try {
    const conn = strapi && strapi.db && strapi.db.connection;
    if (!conn) return { ok: false, reason: 'database unavailable' };
    await ensureColumn('audit_logs', 'prev_hash');
    await ensureColumn('audit_logs', 'entry_hash');
    await ensureColumn('audit_logs', 'created_at_ms');
    const rows = await conn('audit_logs').orderBy('id', 'asc').select('*');
    const seenHashes = new Set([AUDIT_GENESIS]);
    let hashedSeen = false;
    for (const row of rows) {
      if (!row.entry_hash || !row.prev_hash) {
        // Rows written before this patch have no hashes and are unanchored
        // (chain start). New hashed entries must reference a real prior hash,
        // so any unhashed row appearing after the chain started is tampering.
        if (hashedSeen) {
          return { ok: false, entry_id: row.id, reason: 'unhashed entry after chain start (log modified)' };
        }
        continue;
      }
      hashedSeen = true;
      if (!seenHashes.has(row.prev_hash)) {
        return { ok: false, entry_id: row.id, reason: 'prev_hash mismatch (chain broken)' };
      }
      const payload = {
        action: row.action,
        target_email: row.target_email,
        ip: row.ip,
        user_agent: row.user_agent,
        result: row.result,
      };
      if (row.username) payload.username = row.username;
      const expected = sha256(
        auditChainInput({ prevHash: row.prev_hash, payload, createdAtMs: Number(row.created_at_ms) })
      );
      if (expected !== row.entry_hash) {
        return { ok: false, entry_id: row.id, reason: 'entry_hash mismatch (log modified)' };
      }
      seenHashes.add(row.entry_hash);
    }
    return { ok: true, entries: rows.length };
  } catch (err) {
    if (strapi && strapi.log) strapi.log.error(err);
    return { ok: false, reason: String((err && err.message) || err) };
  }
};

module.exports = {
  sha256,
  safeEqual,
  createAttemptTracker,
  tokenData,
  tokenValid,
  otaData,
  otaValid,
  checkPasswordPolicy,
  ensureTable,
  ensureColumn,
  audit: auditEntry,
  verifyAuditChain,
  AUDIT_GENESIS,
  RESET_TOKEN_TTL_MS,
  MFA_CODE_TTL_MS,
};