const { execFile } = require("node:child_process");
const { promisify } = require("node:util");
const db = require("../config/db");
const { ssl } = require("../config/app");
const { alertDomainUsers } = require("./telegram-alerts");

const execFileAsync = promisify(execFile);
const queued = new Set();
let workerChain = Promise.resolve();
let retryTimer = null;

const cleanError = (error) => {
  const raw =
    error?.stderr || error?.stdout || error?.message || "SSL provisioning failed";
  return String(raw).replace(/\s+/g, " ").trim().slice(0, 700);
};

const parseProvisionResult = (stdout) => {
  const lines = String(stdout || "")
    .split(/\r?\n/)
    .map((line) => line.trim())
    .filter(Boolean)
    .reverse();
  for (const line of lines) {
    if (!line.startsWith("{")) continue;
    try {
      return JSON.parse(line);
    } catch (_) {
      // Certbot may emit other structured lines; keep looking.
    }
  }
  return {};
};

const provisionDomainSsl = async (domainId, { force = false } = {}) => {
  if (!ssl.enabled) return { queued: false, reason: "disabled" };

  const result = await db.query(
    `SELECT id, domain_url, user_id, ssl_status, ssl_attempts
     FROM domains WHERE id=$1 LIMIT 1`,
    [domainId]
  );
  if (!result.rowCount) return { queued: false, reason: "not_found" };

  const domain = result.rows[0];
  const attempts = Number(domain.ssl_attempts || 0);
  if (!force && domain.ssl_status === "active") {
    return { queued: false, reason: "already_active" };
  }
  if (!force && attempts >= ssl.maxAttempts) {
    return { queued: false, reason: "attempt_limit" };
  }

  await db.query(
    `UPDATE domains
     SET ssl_status='provisioning', ssl_error=NULL,
         ssl_attempts=ssl_attempts + 1, ssl_updated_at=now()
     WHERE id=$1`,
    [domainId]
  );

  try {
    const { stdout } = await execFileAsync(ssl.command, [domain.domain_url], {
      timeout: ssl.timeoutMs,
      windowsHide: true,
      maxBuffer: 1024 * 1024,
      env: process.env,
    });
    const provisioned = parseProvisionResult(stdout);
    const expiresAt = provisioned.expires_at || null;
    await db.query(
      `UPDATE domains
       SET ssl_status='active', ssl_error=NULL, ssl_updated_at=now(),
           ssl_expires_at=$2
       WHERE id=$1`,
      [domainId, expiresAt]
    );
    alertDomainUsers(domain.id, {
      severity: "success",
      title: "SSL đã sẵn sàng",
      lines: [domain.domain_url, ...(expiresAt ? [`Hết hạn: ${expiresAt}`] : [])],
      dedupeKey: `ssl-active:${domain.domain_url}:${expiresAt || "unknown"}`,
    }).catch((alertError) =>
      console.error("Telegram SSL success alert failed:", alertError.message)
    );
    return { queued: true, status: "active", expiresAt };
  } catch (error) {
    const message = cleanError(error);
    await db.query(
      `UPDATE domains
       SET ssl_status='error', ssl_error=$2, ssl_updated_at=now()
       WHERE id=$1`,
      [domainId, message]
    );
    console.error(`SSL provisioning failed for ${domain.domain_url}: ${message}`);
    alertDomainUsers(domain.id, {
      severity: "error",
      title: "Không thể cấp SSL cho domain",
      lines: [domain.domain_url, `Lỗi: ${message}`],
      dedupeKey: `ssl-error:${domain.domain_url}:${message}`,
      cooldownMs: 30 * 60000,
    }).catch((alertError) =>
      console.error("Telegram SSL error alert failed:", alertError.message)
    );
    return { queued: true, status: "error", error: message };
  }
};

const queueDomainSsl = (domainId, options = {}) => {
  if (!ssl.enabled) return false;
  const id = Number.parseInt(domainId, 10);
  if (!Number.isInteger(id) || queued.has(id)) return false;

  queued.add(id);
  workerChain = workerChain
    .catch(() => undefined)
    .then(() => provisionDomainSsl(id, options))
    .finally(() => queued.delete(id));
  return true;
};

const resumePendingSsl = async () => {
  if (!ssl.enabled) return;
  const result = await db.query(
    `SELECT id
     FROM domains
     WHERE ssl_attempts < $1
       AND (
         ssl_status='pending'
         OR (ssl_status='provisioning' AND ssl_updated_at < now() - interval '10 minutes')
         OR (ssl_status='error' AND ssl_updated_at < now() - interval '30 minutes')
       )
     ORDER BY id ASC
     LIMIT 20`,
    [ssl.maxAttempts]
  );
  result.rows.forEach((row) => queueDomainSsl(row.id));
};

const startSslProvisioner = () => {
  if (!ssl.enabled || retryTimer) return;
  resumePendingSsl().catch((error) =>
    console.error("Unable to resume pending SSL jobs:", error.message)
  );
  retryTimer = setInterval(() => {
    resumePendingSsl().catch((error) =>
      console.error("Unable to scan pending SSL jobs:", error.message)
    );
  }, Math.max(60000, ssl.retryIntervalMs));
  retryTimer.unref?.();
};

const stopSslProvisioner = () => {
  if (retryTimer) clearInterval(retryTimer);
  retryTimer = null;
};

module.exports = {
  provisionDomainSsl,
  queueDomainSsl,
  resumePendingSsl,
  startSslProvisioner,
  stopSslProvisioner,
};
