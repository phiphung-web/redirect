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
    max: parseInteger(process.env.DB_POOL_MAX, 50),
  },
  session: {
    name: process.env.SESSION_NAME || "connect.sid",
    secret: process.env.SESSION_SECRET || "v2_secret_final_rbac",
    maxAgeMs: parseInteger(process.env.SESSION_MAX_AGE_MS, 86400000),
    secure: parseSessionSecure(process.env.SESSION_SECURE),
  },
};
