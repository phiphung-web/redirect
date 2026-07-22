require("dotenv").config({ quiet: true });
const crypto = require("node:crypto");
const db = require("../config/db");
const { telegram, product } = require("../config/app");
const { sendTelegramMessage, telegramReady } = require("./telegram-alerts");

const OFFSET_KEY = "telegram_update_offset";
let stopped = false;

const hashConnectCode = (code) =>
  crypto.createHash("sha256").update(String(code || "").trim().toUpperCase()).digest("hex");

const parseCommand = (text) => {
  const match = String(text || "").trim().match(/^\/(start|connect|disconnect|status)(?:@\w+)?(?:\s+([A-Za-z0-9-]+))?$/i);
  return match ? { command: match[1].toLowerCase(), argument: match[2] || "" } : null;
};

const getOffset = async () => {
  const result = await db.query(
    `SELECT setting_value FROM app_settings WHERE setting_key=$1 LIMIT 1`,
    [OFFSET_KEY]
  );
  return Number.parseInt(result.rows[0]?.setting_value || "0", 10) || 0;
};

const saveOffset = async (offset) => {
  await db.query(
    `INSERT INTO app_settings (setting_key, setting_value, updated_at)
     VALUES ($1, $2::jsonb, now())
     ON CONFLICT (setting_key) DO UPDATE
       SET setting_value=EXCLUDED.setting_value, updated_at=now()`,
    [OFFSET_KEY, JSON.stringify(offset)]
  );
};

const connectUser = async ({ code, chatId, username }) => {
  const client = await db.connect();
  try {
    await client.query("BEGIN");
    const result = await client.query(
      `SELECT id, username
       FROM users
       WHERE telegram_connect_code_hash=$1
         AND telegram_connect_expires_at > now()
         AND is_active=true
       FOR UPDATE`,
      [hashConnectCode(code)]
    );
    if (!result.rowCount) {
      await client.query("ROLLBACK");
      return null;
    }
    const user = result.rows[0];
    await client.query(
      `UPDATE users
       SET telegram_chat_id=NULL, telegram_username=NULL, telegram_connected_at=NULL
       WHERE telegram_chat_id=$1 AND id<>$2`,
      [String(chatId), user.id]
    );
    await client.query(
      `UPDATE users
       SET telegram_chat_id=$1, telegram_username=$2, telegram_connected_at=now(),
           telegram_connect_code_hash=NULL, telegram_connect_expires_at=NULL
       WHERE id=$3`,
      [String(chatId), username || null, user.id]
    );
    await client.query("COMMIT");
    return user;
  } catch (error) {
    await client.query("ROLLBACK");
    throw error;
  } finally {
    client.release();
  }
};

const disconnectChat = async (chatId) => {
  const result = await db.query(
    `UPDATE users
     SET telegram_chat_id=NULL, telegram_username=NULL, telegram_connected_at=NULL
     WHERE telegram_chat_id=$1 RETURNING id`,
    [String(chatId)]
  );
  return result.rowCount > 0;
};

const linkedUser = async (chatId) => {
  const result = await db.query(
    `SELECT u.username, r.name AS role_name
     FROM users u JOIN roles r ON r.id=u.role_id
     WHERE u.telegram_chat_id=$1 AND u.is_active=true LIMIT 1`,
    [String(chatId)]
  );
  return result.rows[0] || null;
};

const handleMessage = async (message) => {
  if (!message?.chat?.id || message.chat.type !== "private") return;
  const chatId = String(message.chat.id);
  const parsed = parseCommand(message.text);
  if (!parsed) {
    await sendTelegramMessage(chatId, `Dùng /connect MÃ để kết nối tài khoản ${product.name}.`, { cooldownMs: 0 });
    return;
  }

  if (parsed.command === "disconnect") {
    const disconnected = await disconnectChat(chatId);
    await sendTelegramMessage(chatId, disconnected ? "Đã ngắt kết nối tài khoản." : "Telegram này chưa được kết nối.", { cooldownMs: 0 });
    return;
  }

  if (parsed.command === "status") {
    const user = await linkedUser(chatId);
    await sendTelegramMessage(chatId, user ? `Đang kết nối với ${user.username} (${user.role_name}).` : "Telegram này chưa được kết nối.", { cooldownMs: 0 });
    return;
  }

  if (!parsed.argument) {
    await sendTelegramMessage(chatId, `Mở ${product.name}, tạo mã kết nối rồi gửi /connect MÃ.`, { cooldownMs: 0 });
    return;
  }

  const user = await connectUser({
    code: parsed.argument,
    chatId,
    username: message.from?.username || null,
  });
  await sendTelegramMessage(
    chatId,
    user ? `✅ Đã kết nối Telegram với tài khoản ${user.username}.` : "Mã không đúng hoặc đã hết hạn. Hãy tạo mã mới trong hệ thống.",
    { cooldownMs: 0 }
  );
};

const getUpdates = async (offset) => {
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), 35000);
  try {
    const response = await fetch(`https://api.telegram.org/bot${telegram.botToken}/getUpdates`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ offset, timeout: 25, allowed_updates: ["message"] }),
      signal: controller.signal,
    });
    const payload = await response.json();
    if (!response.ok || !payload.ok) throw new Error(payload.description || `Telegram HTTP ${response.status}`);
    return payload.result || [];
  } finally {
    clearTimeout(timeout);
  }
};

const delay = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

const startBot = async () => {
  if (!telegramReady()) {
    console.log("Telegram bot disabled");
    return;
  }
  let offset = await getOffset();
  console.log(`${product.name} Telegram bot started`);
  while (!stopped) {
    try {
      const updates = await getUpdates(offset);
      for (const update of updates) {
        try {
          await handleMessage(update.message);
        } catch (error) {
          console.error("Telegram update failed:", error.message);
        }
        offset = update.update_id + 1;
        await saveOffset(offset);
      }
    } catch (error) {
      if (!stopped) {
        console.error("Telegram polling failed:", error.message);
        await delay(5000);
      }
    }
  }
};

process.on("SIGTERM", () => { stopped = true; });
process.on("SIGINT", () => { stopped = true; });

if (require.main === module) {
  startBot().catch((error) => {
    console.error("Telegram bot stopped:", error.message);
    process.exitCode = 1;
  });
}

module.exports = {
  connectUser,
  disconnectChat,
  getUpdates,
  handleMessage,
  hashConnectCode,
  linkedUser,
  parseCommand,
  startBot,
};
