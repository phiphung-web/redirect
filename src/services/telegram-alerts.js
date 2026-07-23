const db = require("../config/db");
const { telegram, product } = require("../config/app");

const recentAlerts = new Map();

const cleanText = (value, maxLength = 500) =>
  String(value ?? "")
    .replace(/[\u0000-\u001f\u007f]/g, " ")
    .replace(/\s+/g, " ")
    .trim()
    .slice(0, maxLength);

const cleanMessage = (value) => String(value ?? "").trim().slice(0, 3900);

const formatAlert = ({ title, lines = [], severity = "warning" }) => {
  const icon = severity === "error" ? "🚨" : severity === "success" ? "✅" : "⚠️";
  return cleanMessage(
    [`${icon} ${cleanText(title, 160)}`, ...lines.filter(Boolean).map((line) => cleanText(line))].join("\n")
  );
};

const telegramReady = () => Boolean(telegram.enabled && telegram.botToken);

const sendTelegramMessage = async (
  chatId,
  message,
  { dedupeKey = "", cooldownMs = telegram.alertCooldownMs } = {}
) => {
  if (!telegramReady() || !chatId) return { skipped: true };
  const key = dedupeKey ? `${chatId}:${dedupeKey}` : "";
  const now = Date.now();
  if (key && now - (recentAlerts.get(key) || 0) < cooldownMs) {
    return { skipped: true, duplicate: true };
  }

  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), telegram.requestTimeoutMs);
  try {
    const response = await fetch(
      `https://api.telegram.org/bot${telegram.botToken}/sendMessage`,
      {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({
          chat_id: String(chatId),
          text: cleanMessage(message),
          disable_web_page_preview: true,
        }),
        signal: controller.signal,
      }
    );
    const payload = await response.json().catch(() => ({}));
    if (!response.ok || !payload.ok) {
      throw new Error(payload.description || `Telegram HTTP ${response.status}`);
    }
    if (key) recentAlerts.set(key, now);
    return payload.result;
  } finally {
    clearTimeout(timeout);
  }
};

const getUserRecipient = async (userId) => {
  const result = await db.query(
    `SELECT id, telegram_chat_id
     FROM users
     WHERE id=$1 AND is_active=true AND telegram_chat_id IS NOT NULL
       AND telegram_link_alerts=true
     LIMIT 1`,
    [userId]
  );
  return result.rows[0] || null;
};

const alertUser = async (userId, options) => {
  if (!telegramReady() || !userId) return { skipped: true };
  const recipient = await getUserRecipient(userId);
  if (!recipient) return { skipped: true };
  return sendTelegramMessage(recipient.telegram_chat_id, formatAlert(options), {
    dedupeKey: options.dedupeKey || "",
    cooldownMs: options.cooldownMs,
  });
};

const getDomainRecipients = async (domainId) => {
  const result = await db.query(
    `SELECT DISTINCT u.id, u.telegram_chat_id
     FROM domain_user_access dua
     JOIN users u ON u.id=dua.user_id
     WHERE dua.domain_id=$1
       AND u.is_active=true
       AND u.telegram_chat_id IS NOT NULL
       AND u.telegram_link_alerts=true
     ORDER BY u.id`,
    [domainId]
  );
  return result.rows;
};

const alertDomainUsers = async (domainId, options) => {
  if (!telegramReady() || !domainId) return [];
  const recipients = await getDomainRecipients(domainId);
  return Promise.allSettled(
    recipients.map((recipient) =>
      sendTelegramMessage(
        recipient.telegram_chat_id,
        formatAlert(options),
        {
          dedupeKey: options.dedupeKey || "",
          cooldownMs: options.cooldownMs,
        }
      )
    )
  );
};

const getSystemRecipients = async () => {
  const recipients = new Set();
  if (telegram.adminChatId) recipients.add(telegram.adminChatId);
  const result = await db.query(
    `SELECT DISTINCT u.telegram_chat_id
     FROM users u
     JOIN roles r ON r.id=u.role_id
     WHERE u.is_active=true AND r.name='super_admin'
       AND u.telegram_chat_id IS NOT NULL
       AND u.telegram_system_alerts=true`
  );
  result.rows.forEach((row) => recipients.add(String(row.telegram_chat_id)));
  return [...recipients];
};

const alertSystem = async (options) => {
  if (!telegramReady()) return [];
  const recipients = await getSystemRecipients();
  return Promise.allSettled(
    recipients.map((chatId) =>
      sendTelegramMessage(chatId, formatAlert(options), {
        dedupeKey: options.dedupeKey || "",
        cooldownMs: options.cooldownMs,
      })
    )
  );
};

const notifyConfigError = (req, area, error, details = []) => {
  const userId = req.session?.user?.id;
  if (!userId) return;
  alertUser(userId, {
    title: `${product.name}: cấu hình chưa hợp lệ`,
    severity: "warning",
    lines: [`Mục: ${area}`, `Lỗi: ${error?.message || error}`, ...details],
    dedupeKey: `config:${userId}:${area}:${cleanText(error?.message || error, 120)}`,
  }).catch((alertError) => console.error("Telegram config alert:", alertError.message));
};

module.exports = {
  alertDomainUsers,
  alertSystem,
  alertUser,
  cleanMessage,
  cleanText,
  formatAlert,
  getDomainRecipients,
  getSystemRecipients,
  getUserRecipient,
  notifyConfigError,
  sendTelegramMessage,
  telegramReady,
};
