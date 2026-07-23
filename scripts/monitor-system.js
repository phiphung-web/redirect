require("dotenv").config({ quiet: true });
const dns = require("node:dns").promises;
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const tls = require("node:tls");
const db = require("../src/config/db");
const { monitoring, product } = require("../src/config/app");
const { alertSystem, alertUser, telegramReady } = require("../src/services/telegram-alerts");

const issue = (message, userIds = []) => ({
  message,
  userIds: Array.isArray(userIds)
    ? userIds.filter(Boolean)
    : userIds
      ? [userIds]
      : [],
});

const fetchHealth = async (label, url) => {
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), 7000);
  try {
    const response = await fetch(url, { signal: controller.signal });
    if (!response.ok) return issue(`${label}: HTTP ${response.status}`);
    return null;
  } catch (error) {
    return issue(`${label}: không truy cập được (${error.message})`);
  } finally {
    clearTimeout(timeout);
  }
};

const checkResources = () => {
  const issues = [];
  const memoryUsed = Math.round((1 - os.freemem() / os.totalmem()) * 100);
  if (memoryUsed >= monitoring.memoryUsagePercent) {
    issues.push(issue(`RAM đang dùng ${memoryUsed}%`));
  }
  if (typeof fs.statfsSync === "function") {
    const stats = fs.statfsSync(monitoring.diskPath);
    const used = Math.round((1 - Number(stats.bavail) / Number(stats.blocks)) * 100);
    if (used >= monitoring.diskUsagePercent) {
      issues.push(issue(`Ổ đĩa ${monitoring.diskPath} đang dùng ${used}%`));
    }
  }
  return issues;
};

const checkBackup = () => {
  const backupDir = path.resolve(process.env.BACKUP_DIR || "./backups");
  if (!fs.existsSync(backupDir)) return issue(`Chưa thấy thư mục backup: ${backupDir}`);
  const files = fs.readdirSync(backupDir)
    .filter((name) => name.endsWith(".dump"))
    .map((name) => fs.statSync(path.join(backupDir, name)).mtimeMs);
  if (!files.length) return issue("Chưa có bản backup cơ sở dữ liệu");
  const ageHours = (Date.now() - Math.max(...files)) / 3600000;
  if (ageHours > monitoring.backupMaxAgeHours) {
    return issue(`Backup mới nhất đã ${Math.round(ageHours)} giờ`);
  }
  return null;
};

const checkTlsExpiry = (hostname) => new Promise((resolve) => {
  const socket = tls.connect({ host: hostname, port: 443, servername: hostname, timeout: 7000 });
  socket.once("secureConnect", () => {
    const cert = socket.getPeerCertificate();
    socket.destroy();
    const expiresAt = Date.parse(cert.valid_to || "");
    if (!Number.isFinite(expiresAt)) return resolve("không đọc được hạn SSL");
    const days = Math.floor((expiresAt - Date.now()) / 86400000);
    return resolve(days <= monitoring.sslExpiryWarningDays ? `SSL còn ${days} ngày` : null);
  });
  socket.once("timeout", () => { socket.destroy(); resolve("SSL timeout"); });
  socket.once("error", (error) => resolve(`SSL lỗi (${error.message})`));
});

const inspectLinkConfiguration = (row, type) => {
  const issues = [];
  try {
    const target = new URL(row.target_url);
    if (!/^https?:$/.test(target.protocol)) throw new Error("protocol");
  } catch (_) {
    issues.push(`${type} #${row.id}: URL đích không hợp lệ`);
  }
  if (type === "Link điều kiện") {
    const rules = Array.isArray(row.rules) ? row.rules : [];
    if (!rules.length) issues.push(`${type} #${row.id}: chưa có rule kiểm tra`);
  }
  if (type === "Link tự động") {
    const delay = Number(row.redirect_delay_seconds);
    if (!Number.isInteger(delay) || delay < 1 || delay > 30) {
      issues.push(`${type} #${row.id}: thời gian chờ ngoài khoảng 1–30 giây`);
    }
  }
  return issues;
};

const checkDomainsAndLinks = async () => {
  const issues = [];
  const domains = await db.query(
    `SELECT d.id, d.domain_url, d.ssl_status, d.ssl_error,
            COALESCE(array_agg(dua.user_id) FILTER (WHERE dua.user_id IS NOT NULL), '{}') AS user_ids
     FROM domains d
     LEFT JOIN domain_user_access dua ON dua.domain_id=d.id
     WHERE d.status='active'
     GROUP BY d.id
     ORDER BY d.id`
  );
  for (const domain of domains.rows) {
    try {
      const addresses = await dns.resolve4(domain.domain_url);
      if (monitoring.expectedIpv4 && !addresses.includes(monitoring.expectedIpv4)) {
        issues.push(issue(`${domain.domain_url}: DNS không trỏ về ${monitoring.expectedIpv4}`, domain.user_ids));
      }
    } catch (error) {
      issues.push(issue(`${domain.domain_url}: DNS lỗi (${error.code || error.message})`, domain.user_ids));
    }
    if (["error", "fallback"].includes(domain.ssl_status)) {
      issues.push(issue(`${domain.domain_url}: SSL ${domain.ssl_status}${domain.ssl_error ? ` – ${domain.ssl_error}` : ""}`, domain.user_ids));
    } else if (domain.ssl_status === "active") {
      const tlsIssue = await checkTlsExpiry(domain.domain_url);
      if (tlsIssue) issues.push(issue(`${domain.domain_url}: ${tlsIssue}`, domain.user_ids));
    }
  }

  const campaigns = await db.query(
    `SELECT c.id, c.target_url, c.rules,
            COALESCE(array_agg(dua.user_id) FILTER (WHERE dua.user_id IS NOT NULL), '{}') AS user_ids
     FROM campaigns c
     LEFT JOIN domain_user_access dua ON dua.domain_id=c.domain_id
     WHERE c.is_active=true
     GROUP BY c.id`
  );
  campaigns.rows.forEach((row) => {
    inspectLinkConfiguration(row, "Link điều kiện").forEach((message) => issues.push(issue(message, row.user_ids)));
  });
  const shortLinks = await db.query(
    `SELECT s.id, s.target_url, s.redirect_delay_seconds,
            COALESCE(array_agg(dua.user_id) FILTER (WHERE dua.user_id IS NOT NULL), '{}') AS user_ids
     FROM short_links s
     LEFT JOIN domain_user_access dua ON dua.domain_id=s.domain_id
     WHERE s.is_active=true
     GROUP BY s.id`
  );
  shortLinks.rows.forEach((row) => {
    inspectLinkConfiguration(row, "Link tự động").forEach((message) => issues.push(issue(message, row.user_ids)));
  });
  return issues;
};

const loadState = () => {
  try { return JSON.parse(fs.readFileSync(monitoring.stateFile, "utf8")); } catch (_) { return {}; }
};

const saveState = (state) => {
  fs.mkdirSync(path.dirname(path.resolve(monitoring.stateFile)), { recursive: true, mode: 0o700 });
  const temp = `${monitoring.stateFile}.tmp`;
  fs.writeFileSync(temp, JSON.stringify(state, null, 2), { mode: 0o600 });
  fs.renameSync(temp, monitoring.stateFile);
};

const fingerprint = (messages) => [...messages].sort().join("|");

const parseRuleFailureDetail = (action, rawReferer) => {
  const raw = String(rawReferer || "");
  const detail = raw.includes("detail=")
    ? raw.slice(raw.lastIndexOf("detail=") + 7).trim()
    : "";
  if (action === "safe_page_missing_param") {
    const key = detail.startsWith("missing:") ? detail.slice(8) : "không xác định";
    return `Thiếu tham số ${key}`;
  }
  const match = detail.match(/^expect ([^=;\s]+)=([^;]*);\s*got=(.*)$/i);
  if (match) {
    return `Sai ${match[1]}: cần "${match[2]}", nhận "${match[3]}"`;
  }
  return "Giá trị tham số không khớp";
};

const getRuleFailureCursor = async () => {
  const result = await db.query(
    `SELECT COALESCE(MAX(id), 0)::bigint AS last_id
     FROM traffic_logs
     WHERE action IN ('safe_page_missing_param', 'safe_page_wrong_param_val')`
  );
  return String(result.rows[0]?.last_id || "0");
};

const getRuleFailuresAfter = async (lastId) => {
  const result = await db.query(
    `SELECT tl.id, tl.campaign_id, tl.action, tl.referer,
            c.name AS campaign_name, d.domain_url,
            COALESCE(
              array_agg(DISTINCT dua.user_id)
                FILTER (WHERE dua.user_id IS NOT NULL),
              '{}'
            ) AS user_ids
     FROM traffic_logs tl
     JOIN campaigns c ON c.id=tl.campaign_id
     JOIN domains d ON d.id=tl.domain_id
     LEFT JOIN domain_user_access dua ON dua.domain_id=tl.domain_id
     WHERE tl.id > $1::bigint
       AND tl.created_at >= now() - interval '24 hours'
       AND tl.action IN ('safe_page_missing_param', 'safe_page_wrong_param_val')
     GROUP BY tl.id, tl.campaign_id, tl.action, tl.referer,
              c.name, d.domain_url
     ORDER BY tl.id ASC
     LIMIT 5000`,
    [String(lastId || "0")]
  );
  return result.rows;
};

const groupRuleFailuresByUser = (rows) => {
  const byUser = new Map();
  rows.forEach((row) => {
    const reason = parseRuleFailureDetail(row.action, row.referer);
    (row.user_ids || []).forEach((userId) => {
      const id = String(userId);
      if (!byUser.has(id)) byUser.set(id, new Map());
      const groups = byUser.get(id);
      const key = `${row.campaign_id}:${reason}`;
      const current = groups.get(key) || {
        domain: row.domain_url,
        campaign: row.campaign_name,
        reason,
        count: 0,
      };
      current.count += 1;
      groups.set(key, current);
    });
  });
  return byUser;
};

const sendRuleFailureAlerts = async (state) => {
  state.ruleFailures ||= { lastId: null, users: {} };
  if (state.ruleFailures.lastId === null) {
    state.ruleFailures.lastId = await getRuleFailureCursor();
    return;
  }

  const rows = await getRuleFailuresAfter(state.ruleFailures.lastId);
  if (!rows.length) return;

  state.ruleFailures.lastId = String(rows[rows.length - 1].id);
  const byUser = groupRuleFailuresByUser(rows);
  const cooldownMs = monitoring.ruleFailureAlertCooldownMinutes * 60000;
  const now = Date.now();

  for (const [userId, groups] of byUser) {
    const lastSentAt = Number(state.ruleFailures.users[userId] || 0);
    if (now - lastSentAt < cooldownMs) continue;
    const lines = [...groups.values()].slice(0, 10).map(
      (item) =>
        `${item.domain} · ${item.campaign}: ${item.count} lượt bị chặn — ${item.reason}`
    );
    if (groups.size > lines.length) {
      lines.push(`Và ${groups.size - lines.length} lỗi khác.`);
    }
    await alertUser(userId, {
      title: `${product.name}: traffic không khớp rule`,
      severity: "warning",
      lines,
      cooldownMs: 0,
    });
    state.ruleFailures.users[userId] = now;
  }
};

const shouldAlert = (previous, messages) => {
  const nextFingerprint = fingerprint(messages);
  const repeatMs = monitoring.repeatMinutes * 60000;
  return {
    send: previous?.fingerprint !== nextFingerprint || Date.now() - (previous?.sentAt || 0) >= repeatMs,
    state: { fingerprint: nextFingerprint, sentAt: Date.now(), hasIssues: messages.length > 0 },
  };
};

const sendScope = async ({ key, messages, userId, previous }) => {
  const decision = shouldAlert(previous, messages);
  const recovered = previous?.hasIssues && messages.length === 0;
  if (recovered) {
    const options = { title: `${product.name}: đã hoạt động bình thường`, severity: "success", lines: ["Các lỗi được báo trước đó không còn xuất hiện."], dedupeKey: `recovery:${key}`, cooldownMs: 0 };
    if (userId) await alertUser(userId, options); else await alertSystem(options);
  } else if (messages.length && decision.send) {
    const options = { title: `${product.name}: phát hiện bất thường`, severity: "error", lines: messages.slice(0, 12), dedupeKey: `monitor:${key}:${fingerprint(messages)}`, cooldownMs: 0 };
    if (userId) await alertUser(userId, options); else await alertSystem(options);
  }
  return { ...decision.state, sentAt: recovered || (messages.length && decision.send) ? Date.now() : previous?.sentAt || 0 };
};

const runMonitor = async () => {
  const globalIssues = [];
  globalIssues.push(await fetchHealth("Admin", monitoring.adminHealthUrl));
  globalIssues.push(await fetchHealth("Ads", monitoring.adsHealthUrl));
  try { await db.query("SELECT 1"); } catch (error) { globalIssues.push(issue(`Database lỗi (${error.message})`)); }
  try { globalIssues.push(...checkResources()); } catch (error) { globalIssues.push(issue(`Không đọc được tài nguyên máy chủ (${error.message})`)); }
  try { globalIssues.push(checkBackup()); } catch (error) { globalIssues.push(issue(`Không kiểm tra được backup (${error.message})`)); }

  let resourceIssues = [];
  try { resourceIssues = await checkDomainsAndLinks(); } catch (error) { globalIssues.push(issue(`Không kiểm tra được domain/link (${error.message})`)); }

  const byUser = new Map();
  resourceIssues.forEach((item) => {
    if (!item.userIds.length) return globalIssues.push(item);
    item.userIds.forEach((userId) => {
      const id = String(userId);
      if (!byUser.has(id)) byUser.set(id, []);
      byUser.get(id).push(item.message);
    });
  });

  const state = loadState();
  try {
    await sendRuleFailureAlerts(state);
  } catch (error) {
    globalIssues.push(issue(`Không kiểm tra được traffic fail rule (${error.message})`));
  }
  state.system = await sendScope({ key: "system", messages: globalIssues.filter(Boolean).map((item) => item.message), previous: state.system });
  state.users ||= {};
  const knownUsers = new Set([...Object.keys(state.users), ...byUser.keys()]);
  for (const userId of knownUsers) {
    state.users[userId] = await sendScope({ key: `user:${userId}`, userId, messages: byUser.get(userId) || [], previous: state.users[userId] });
  }
  saveState(state);
  const count = globalIssues.filter(Boolean).length + resourceIssues.length;
  console.log(`Monitor complete: ${count} issue(s); Telegram ${telegramReady() ? "enabled" : "disabled"}`);
};

if (require.main === module) {
  runMonitor()
    .catch((error) => { console.error("Monitor failed:", error); process.exitCode = 1; })
    .finally(() => db.end());
}

module.exports = {
  checkBackup,
  checkResources,
  fingerprint,
  getRuleFailuresAfter,
  groupRuleFailuresByUser,
  inspectLinkConfiguration,
  parseRuleFailureDetail,
  runMonitor,
  sendRuleFailureAlerts,
  shouldAlert,
};
