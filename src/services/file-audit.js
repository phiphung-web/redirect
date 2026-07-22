const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");

const configuredPath = path.resolve(
  process.env.AUDIT_FILE_PATH ||
    (process.env.NODE_ENV === "production"
      ? "/var/log/linkpilot/audit.log"
      : path.join(os.tmpdir(), "linkpilot-audit.log"))
);
const auditDirectory = path.dirname(configuredPath);
const auditBaseName = path.basename(configuredPath, path.extname(configuredPath));
const maxBytes = Math.max(
  1024 * 1024,
  Number.parseInt(process.env.AUDIT_FILE_MAX_MB || "20", 10) * 1024 * 1024
);
const retentionDays = Math.min(
  30,
  Math.max(1, Number.parseInt(process.env.AUDIT_RETENTION_DAYS || "7", 10))
);

let initialized = false;
let lastCleanupDate = "";

const dateStamp = (date = new Date()) =>
  new Intl.DateTimeFormat("en-CA", {
    timeZone: "Asia/Ho_Chi_Minh",
    year: "numeric",
    month: "2-digit",
    day: "2-digit",
  }).format(date);

const currentAuditPath = () =>
  path.join(auditDirectory, `${auditBaseName}-${dateStamp()}.log`);

const initialize = () => {
  if (initialized) return;
  fs.mkdirSync(auditDirectory, { recursive: true, mode: 0o700 });
  initialized = true;
};

const cleanupExpiredFiles = () => {
  initialize();
  const today = dateStamp();
  if (lastCleanupDate === today) return;
  lastCleanupDate = today;
  const cutoff = Date.now() - retentionDays * 86400000;
  const prefix = `${auditBaseName}-`;
  for (const file of fs.readdirSync(auditDirectory)) {
    if (!file.startsWith(prefix) || !file.includes(".log")) continue;
    const fullPath = path.join(auditDirectory, file);
    try {
      if (fs.statSync(fullPath).mtimeMs < cutoff) fs.unlinkSync(fullPath);
    } catch (_) {
      // A concurrent cleanup/rotation may already have handled the file.
    }
  }
};

const rotateIfNeeded = (filePath = currentAuditPath()) => {
  initialize();
  if (!fs.existsSync(filePath)) {
    fs.writeFileSync(filePath, "", { mode: 0o600 });
    return filePath;
  }
  if (fs.statSync(filePath).size < maxBytes) return filePath;
  for (let index = 9; index >= 1; index -= 1) {
    const source = index === 1 ? filePath : `${filePath}.${index - 1}`;
    const destination = `${filePath}.${index}`;
    if (!fs.existsSync(source)) continue;
    if (fs.existsSync(destination)) fs.unlinkSync(destination);
    fs.renameSync(source, destination);
  }
  fs.writeFileSync(filePath, "", { mode: 0o600 });
  return filePath;
};

const appendAuditEvent = (event) => {
  try {
    cleanupExpiredFiles();
    const filePath = rotateIfNeeded();
    fs.appendFileSync(filePath, `${JSON.stringify(event)}\n`, {
      encoding: "utf8",
      mode: 0o600,
    });
  } catch (error) {
    console.error("Private audit file error:", error.message);
  }
};

const fileAuditMiddleware = (req, res, next) => {
  const startedAt = Date.now();
  res.once("finish", () => {
    const user = req.session?.user || null;
    appendAuditEvent({
      timestamp: new Date().toISOString(),
      request_id: req.requestId || null,
      user_id: user?.id || null,
      username: user?.username || null,
      role: user?.role_name || null,
      method: req.method,
      path: req.path,
      status: res.statusCode,
      duration_ms: Date.now() - startedAt,
      ip: req.ip || null,
      user_agent: req.headers?.["user-agent"] || null,
    });
  });
  next();
};

module.exports = {
  appendAuditEvent,
  auditDirectory,
  cleanupExpiredFiles,
  currentAuditPath,
  dateStamp,
  fileAuditMiddleware,
  rotateIfNeeded,
};
