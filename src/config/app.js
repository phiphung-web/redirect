require("dotenv").config({ quiet: true });

const parseBoolean = (value, fallback) => {
  if (value === undefined || value === null || value === "") return fallback;
  return ["1", "true", "yes", "on"].includes(String(value).toLowerCase());
};

const parseInteger = (value, fallback) => {
  const parsed = Number.parseInt(value, 10);
  return Number.isFinite(parsed) ? parsed : fallback;
};

const parseTrustProxy = (value) => {
  if (value === undefined || value === null || value === "") return 1;
  const raw = String(value).trim().toLowerCase();
  if (/^\d+$/.test(raw)) return Number.parseInt(raw, 10);
  if (["loopback", "linklocal", "uniquelocal"].includes(raw)) return raw;
  return parseBoolean(value, true);
};

const parseSessionSecure = (value) => {
  if (value === undefined || value === null || value === "") return "auto";
  const raw = String(value).trim().toLowerCase();
  if (raw === "auto") return "auto";
  return parseBoolean(raw, false);
};

const isProduction = process.env.NODE_ENV === "production";

const product = {
  name: process.env.PRODUCT_NAME || "LinkPilot",
  shortName: process.env.PRODUCT_SHORT_NAME || "LP",
  tagline: process.env.PRODUCT_TAGLINE || "Redirect & Campaign Control",
  support: process.env.PRODUCT_SUPPORT || "",
};

const performance = {
  cacheEnabled: parseBoolean(process.env.CACHE_ENABLED, true),
  cacheTtlMs: parseInteger(process.env.CACHE_TTL_MS, 30000),
  cacheStaleTtlMs: parseInteger(process.env.CACHE_STALE_TTL_MS, 300000),
  cacheMaxEntries: parseInteger(process.env.CACHE_MAX_ENTRIES, 5000),
  trafficBufferEnabled: parseBoolean(
    process.env.TRAFFIC_BUFFER_ENABLED,
    isProduction
  ),
  trafficBatchSize: parseInteger(process.env.TRAFFIC_BATCH_SIZE, 100),
  trafficFlushMs: parseInteger(process.env.TRAFFIC_FLUSH_MS, 1000),
  trafficQueueMax: parseInteger(process.env.TRAFFIC_QUEUE_MAX, 10000),
  counterBufferEnabled: parseBoolean(
    process.env.COUNTER_BUFFER_ENABLED,
    isProduction
  ),
  counterFlushMs: parseInteger(process.env.COUNTER_FLUSH_MS, 2000),
};

const ssl = {
  enabled: parseBoolean(process.env.AUTO_SSL_ENABLED, false),
  command:
    process.env.SSL_PROVISION_COMMAND ||
    "/usr/local/sbin/redirect-pro-provision-domain",
  timeoutMs: Math.max(
    30000,
    parseInteger(process.env.SSL_PROVISION_TIMEOUT_MS, 180000)
  ),
  retryIntervalMs: Math.max(
    60000,
    parseInteger(process.env.SSL_RETRY_INTERVAL_MS, 300000)
  ),
  maxAttempts: Math.max(
    1,
    parseInteger(process.env.SSL_MAX_ATTEMPTS, 5)
  ),
};

const telegram = {
  enabled: parseBoolean(process.env.TELEGRAM_ALERTS_ENABLED, false),
  botToken: String(process.env.TELEGRAM_BOT_TOKEN || "").trim(),
  botUsername: String(process.env.TELEGRAM_BOT_USERNAME || "").trim().replace(/^@/, ""),
  adminChatId: String(
    process.env.TELEGRAM_ADMIN_CHAT_ID || process.env.TELEGRAM_CHAT_ID || ""
  ).trim(),
  requestTimeoutMs: Math.max(
    3000,
    parseInteger(process.env.TELEGRAM_REQUEST_TIMEOUT_MS, 10000)
  ),
  alertCooldownMs:
    Math.max(1, parseInteger(process.env.TELEGRAM_ALERT_COOLDOWN_MINUTES, 15)) *
    60000,
};

const monitoring = {
  expectedIpv4: String(process.env.MONITOR_EXPECTED_IPV4 || "").trim(),
  diskPath: process.env.MONITOR_DISK_PATH || (isProduction ? "/opt/linkpilot" : "."),
  diskUsagePercent: Math.min(
    99,
    Math.max(50, parseInteger(process.env.MONITOR_DISK_USAGE_PERCENT, 85))
  ),
  memoryUsagePercent: Math.min(
    99,
    Math.max(50, parseInteger(process.env.MONITOR_MEMORY_USAGE_PERCENT, 90))
  ),
  backupMaxAgeHours: Math.max(
    1,
    parseInteger(process.env.MONITOR_BACKUP_MAX_AGE_HOURS, 30)
  ),
  sslExpiryWarningDays: Math.max(
    1,
    parseInteger(process.env.MONITOR_SSL_EXPIRY_WARNING_DAYS, 14)
  ),
  repeatMinutes: Math.max(
    15,
    parseInteger(process.env.MONITOR_ALERT_REPEAT_MINUTES, 360)
  ),
  stateFile:
    process.env.MONITOR_STATE_FILE ||
    (isProduction
      ? "/var/lib/linkpilot/monitor-state.json"
      : "./.runtime/monitor-state.json"),
  adminHealthUrl:
    process.env.MONITOR_ADMIN_HEALTH_URL ||
    `http://127.0.0.1:${parseInteger(
      process.env.ADMIN_PORT || process.env.PORT,
      4002
    )}/healthz`,
  adsHealthUrl:
    process.env.MONITOR_ADS_HEALTH_URL ||
    `http://127.0.0.1:${parseInteger(
      process.env.ADS_PORT || process.env.PORT,
      4001
    )}/healthz`,
};

if (isProduction) {
  const unsafeSecrets = [
    "",
    "dev-session-secret-change-me-before-prod",
    "change_this_to_a_long_random_secret",
    "v2_secret_final_rbac",
  ];
  const secret = String(process.env.SESSION_SECRET || "");
  if (unsafeSecrets.includes(secret) || secret.length < 32) {
    throw new Error("SESSION_SECRET must be at least 32 characters in production");
  }
  if (!process.env.DB_PASS || process.env.DB_PASS === "change_this_strong_password") {
    throw new Error("DB_PASS must be configured in production");
  }
}

module.exports = {
  env: process.env.NODE_ENV || "development",
  isProduction,
  ports: {
    ads: parseInteger(process.env.ADS_PORT || process.env.PORT, 4001),
    admin: parseInteger(process.env.ADMIN_PORT || process.env.PORT, 4002),
  },
  trustProxy: parseTrustProxy(process.env.TRUST_PROXY),
  db: {
    user: process.env.DB_USER || "postgres",
    host: process.env.DB_HOST || "localhost",
    database: process.env.DB_NAME || "redirect_v2_db",
    password: process.env.DB_PASS || "123456",
    port: parseInteger(process.env.DB_PORT, 5432),
    max: parseInteger(process.env.DB_POOL_MAX, isProduction ? 10 : 20),
    idleTimeoutMillis: parseInteger(process.env.DB_IDLE_TIMEOUT_MS, 30000),
    connectionTimeoutMillis: parseInteger(
      process.env.DB_CONNECTION_TIMEOUT_MS,
      5000
    ),
  },
  session: {
    name: process.env.SESSION_NAME || "connect.sid",
    secret: process.env.SESSION_SECRET || "v2_secret_final_rbac",
    maxAgeMs: parseInteger(process.env.SESSION_MAX_AGE_MS, 86400000),
    secure: parseSessionSecure(process.env.SESSION_SECURE),
    store: process.env.SESSION_STORE || (isProduction ? "postgres" : "memory"),
    table: process.env.SESSION_TABLE || "user_sessions",
  },
  product,
  performance,
  ssl,
  telegram,
  monitoring,
};
