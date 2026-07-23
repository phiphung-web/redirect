require("dotenv").config({ quiet: true });
const express = require("express");
const crypto = require("node:crypto");
const session = require("express-session");
const PgSession = require("connect-pg-simple")(session);
const helmet = require("helmet");
const path = require("path");
const dns = require("dns");
const os = require("os");
const rateLimit = require("express-rate-limit");
const {
  ports,
  session: sessionConfig,
  trustProxy,
  isProduction,
  product,
  ssl,
  telegram,
} = require("./config/app");
const db = require("./config/db");
const { requestContext } = require("./middleware/request-context");
const { csrfProtection } = require("./middleware/csrf");
const { fileAuditMiddleware } = require("./services/file-audit");
const {
  buildFilters,
  normalizeDomainUrl,
  normalizeSafeTemplate,
  normalizeShortCode,
  normalizeTargetUrl,
  parseRules,
  validateName,
  validateParamKey,
  validateParamValue,
} = require("./utils/validation");
const {
  hashPassword,
  verifyPasswordWithLazyMigration,
} = require("./services/passwords");
const { auditAdminAction } = require("./services/audit");
const {
  queueDomainSsl,
  startSslProvisioner,
  stopSslProvisioner,
} = require("./services/ssl-provisioner");
const {
  notifyConfigError,
  sendTelegramMessage,
} = require("./services/telegram-alerts");
const { hashConnectCode } = require("./services/telegram-bot");

const app = express();
const PORT = ports.admin;
const DEFAULT_TIMEZONE = "Asia/Ho_Chi_Minh";
const loginRateLimit = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 10,
  standardHeaders: true,
  legacyHeaders: false,
  skipSuccessfulRequests: true,
  message: "Too many login attempts. Please try again later.",
});

// Sinh mã ngẫu nhiên.
const generateCode = (len = 8) => {
  const chars =
    "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
  let res = "";
  for (let i = 0; i < len; i++)
    res += chars.charAt(Math.floor(Math.random() * chars.length));
  return res;
};

const generateShortCode = (len = 7) => generateCode(len).toLowerCase();

const parseMonthRange = (monthStr) => {
  const now = new Date();
  const normalized =
    typeof monthStr === "string" && /^\d{4}-\d{2}$/.test(monthStr)
      ? monthStr
      : `${now.getFullYear()}-${String(now.getMonth() + 1).padStart(
          2,
          "0"
        )}`;
  const start = new Date(`${normalized}-01T00:00:00.000Z`);
  const end = new Date(start);
  end.setUTCMonth(end.getUTCMonth() + 1);
  return { normalized, start, end };
};

const buildSystemStatus = async () => {
  let dbStatus = "ok";
  let dbInfo = {
    version: null,
    connections: null,
    active_connections: null,
    idle_connections: null,
    db_size: null,
    cache_hit: null,
    settings: {},
  };
  try {
    const base = await db.query(
      `SELECT version(),
              (SELECT COUNT(*) FROM pg_stat_activity) AS connections,
              (SELECT COUNT(*) FROM pg_stat_activity WHERE state='active') AS active_connections,
              (SELECT COUNT(*) FROM pg_stat_activity WHERE state='idle') AS idle_connections,
              pg_database_size(current_database()) AS db_size`
    );
    const settings = await db.query(
      `SELECT
          current_setting('max_connections')::int AS max_connections,
          current_setting('shared_buffers') AS shared_buffers,
          current_setting('work_mem') AS work_mem,
          current_setting('maintenance_work_mem') AS maintenance_work_mem`
    );
    const cache = await db.query(
      `SELECT blks_hit, blks_read,
              CASE WHEN (blks_hit + blks_read) > 0
                   THEN ROUND(blks_hit * 100.0 / (blks_hit + blks_read), 2)
                   ELSE NULL END AS cache_hit
       FROM pg_stat_database
       WHERE datname = current_database()`
    );
    dbInfo = {
      version: base.rows[0].version,
      connections: Number(base.rows[0].connections || 0),
      active_connections: Number(base.rows[0].active_connections || 0),
      idle_connections: Number(base.rows[0].idle_connections || 0),
      db_size: Number(base.rows[0].db_size || 0),
      cache_hit: cache.rows[0]?.cache_hit || null,
      settings: settings.rows[0] || {},
    };
  } catch (e) {
    dbStatus = "error";
  }
  const load = os.loadavg();
  const memTotal = os.totalmem();
  const memFree = os.freemem();
  const memUsed = memTotal - memFree;
  const cpus = os.cpus();
  return {
    uptime: os.uptime(),
    load1: load[0],
    load5: load[1],
    load15: load[2],
    memTotal,
    memUsed,
    memFree,
    dbStatus,
    dbInfo,
    procMem: process.memoryUsage(),
    procUptime: process.uptime(),
    platform: os.platform(),
    release: os.release(),
    cpuModel: cpus && cpus.length ? cpus[0].model : "N/A",
    cpuCores: cpus ? cpus.length : 0,
    nodeVersion: process.version,
    timezone: DEFAULT_TIMEZONE,
  };
};

const parseLogMeta = (row) => {
  const meta = { ref: null, url: null, detail: null };
  if (row.referer) {
    const parts = row.referer.split(" | ");
    parts.forEach((p) => {
      if (p.startsWith("ref=")) meta.ref = p.slice(4);
      else if (p.startsWith("url=")) meta.url = p.slice(4);
      else if (p.startsWith("detail=")) meta.detail = p.slice(7);
    });
    if (!meta.ref && !meta.url) meta.ref = row.referer;
  }
  return { ...row, meta };
};

app.disable("x-powered-by");
app.set("trust proxy", trustProxy);
app.set("view engine", "ejs");
app.set("views", path.join(__dirname, "views"));
app.use(helmet({ contentSecurityPolicy: false }));
app.use(requestContext);
app.use(express.urlencoded({ extended: true }));
app.use(express.json());
app.use("/assets", express.static(path.join(__dirname, "../public")));
app.use(express.static(path.join(__dirname, "../public")));

app.get("/healthz", async (req, res) => {
  try {
    await db.query("SELECT 1");
    return res.json({
      status: "ok",
      service: "admin",
      product: product.name,
      uptime: Math.round(process.uptime()),
    });
  } catch (error) {
    return res.status(503).json({ status: "error", service: "admin" });
  }
});

const sessionStore =
  sessionConfig.store === "postgres"
    ? new PgSession({
        pool: db,
        tableName: sessionConfig.table,
        createTableIfMissing: true,
      })
    : undefined;

app.use(
  session({
    store: sessionStore,
    name: sessionConfig.name,
    secret: sessionConfig.secret,
    resave: false,
    saveUninitialized: false,
    rolling: true,
    proxy: trustProxy,
    cookie: {
      maxAge: sessionConfig.maxAgeMs,
      httpOnly: true,
      sameSite: "lax",
      secure: sessionConfig.secure === "auto" ? "auto" : !!sessionConfig.secure,
    },
  })
);
app.use(fileAuditMiddleware);
app.use(csrfProtection);
app.use((req, res, next) => {
  res.locals.csrfToken = req.csrfToken();
  res.locals.requestId = req.requestId;
  res.locals.isProduction = isProduction;
  res.locals.product = product;
  res.locals.sslAutomationEnabled = ssl.enabled;
  next();
});

// --- RBAC VÀ QUYỀN SỞ HỮU ---
const checkAuth = (req, res, next) => {
  if (!req.session.user) return res.redirect("/login");
  res.locals.currentUser = req.session.user;
  next();
};

// Chỉ cho phép các role được khai báo truy cập.
const requireRole = (rolesArray) => {
  return (req, res, next) => {
    if (!req.session.user) return res.redirect("/login");
    const userRole = req.session.user.role_name; // 'super_admin' or 'user'

    if (rolesArray.includes(userRole)) {
      next();
    } else {
      res.status(403).send(`Bạn không có quyền truy cập (role: ${userRole})`);
    }
  };
};

const RESOURCE_DOMAIN_EXPRESSIONS = {
  domain: { table: "domains", expression: "id" },
  campaign: { table: "campaigns", expression: "domain_id" },
  shortLink: { table: "short_links", expression: "domain_id" },
};

const requireOwnedResource = (resourceType, getId) => {
  return async (req, res, next) => {
    if (!req.session.user) return res.redirect("/login");
    if (req.session.user.role_name === "super_admin") return next();

    const resource = RESOURCE_DOMAIN_EXPRESSIONS[resourceType];
    const resourceId = Number.parseInt(getId(req), 10);
    if (!resource || !Number.isInteger(resourceId)) {
      return res.status(400).send("Tài nguyên không hợp lệ");
    }

    const result = await db.query(
      `SELECT ${resource.expression} AS domain_id
       FROM ${resource.table}
       WHERE id=$1
       LIMIT 1`,
      [resourceId]
    );
    if (!result.rowCount) {
      return res.status(404).send("Không tìm thấy tài nguyên");
    }
    const access = await db.query(
      `SELECT 1
       FROM domain_user_access
       WHERE domain_id=$1 AND user_id=$2
       LIMIT 1`,
      [result.rows[0].domain_id, req.session.user.id]
    );
    if (!access.rowCount) {
      return res.status(403).send("Bạn không có quyền với tài nguyên này");
    }
    return next();
  };
};

const ownDomainFromBody = requireOwnedResource(
  "domain",
  (req) => req.body.domain_id
);
const ownDomainFromParams = requireOwnedResource(
  "domain",
  (req) => req.params.id
);
const ownCampaignFromParams = requireOwnedResource(
  "campaign",
  (req) => req.params.id
);
const ownSafePageFromParams = (_req, _res, next) => next();
const ownShortLinkFromParams = requireOwnedResource(
  "shortLink",
  (req) => req.params.id
);

// AUTH
app.get("/login", (req, res) => res.render("admin/login", { error: null }));
app.post("/login", loginRateLimit, async (req, res) => {
  const { username, password } = req.body;
  const r = await db.query(
    `
        SELECT u.*, r.name as role_name FROM users u
        JOIN roles r ON u.role_id = r.id
        WHERE u.username = $1 AND u.is_active=true
    `,
    [username]
  );

  if (r.rowCount > 0) {
    const result = await verifyPasswordWithLazyMigration(r.rows[0], password);

    if (result.isValid) {
      await new Promise((resolve, reject) => {
        req.session.regenerate((error) => (error ? reject(error) : resolve()));
      });
      req.session.user = result.user;
      await auditAdminAction({
        req,
        action: "login",
        targetType: "session",
        targetId: result.user.id,
        detail: { username: result.user.username },
      });
      return res.redirect("/");
    }
  }
  await auditAdminAction({
    req,
    action: "login_failed",
    targetType: "session",
    status: "failed",
    detail: { username },
  });
  res.render("admin/login", { error: "Sai thông tin" });
});
const logoutHandler = async (req, res) => {
  await auditAdminAction({
    req,
    action: "logout",
    targetType: "session",
    targetId: req.session?.user?.id || null,
  });
  req.session.destroy(() => res.redirect("/login"));
};
app.get("/logout", (req, res) => res.status(405).send("Use POST /logout"));
app.post("/logout", logoutHandler);

// --- TELEGRAM ACCOUNT LINK ---
app.get("/account/telegram", checkAuth, async (req, res) => {
  const result = await db.query(
    `SELECT telegram_chat_id, telegram_username, telegram_link_alerts,
            telegram_system_alerts, telegram_connected_at,
            telegram_connect_expires_at
     FROM users WHERE id=$1 LIMIT 1`,
    [req.session.user.id]
  );
  const connectCode = req.session.telegramConnectCode || null;
  const notice = req.session.telegramNotice || null;
  delete req.session.telegramConnectCode;
  delete req.session.telegramNotice;
  res.render("admin/telegram_settings", {
    user: req.session.user,
    settings: result.rows[0] || {},
    connectCode,
    notice,
    telegramEnabled: telegram.enabled && Boolean(telegram.botToken),
    telegramBotUsername: telegram.botUsername,
  });
});

app.post("/account/telegram/code", checkAuth, async (req, res) => {
  if (!telegram.enabled || !telegram.botToken) {
    return res.status(503).send("Telegram chưa được cấu hình trên máy chủ");
  }
  const code = crypto.randomBytes(5).toString("hex").toUpperCase();
  await db.query(
    `UPDATE users
     SET telegram_connect_code_hash=$1,
         telegram_connect_expires_at=now() + interval '15 minutes'
     WHERE id=$2`,
    [hashConnectCode(code), req.session.user.id]
  );
  req.session.telegramConnectCode = code;
  await auditAdminAction({
    req,
    action: "telegram_connect_code_create",
    targetType: "user",
    targetId: req.session.user.id,
  });
  return res.redirect("/account/telegram");
});

app.post("/account/telegram/preferences", checkAuth, async (req, res) => {
  const allowSystemAlerts = req.session.user.role_name === "super_admin";
  await db.query(
    `UPDATE users
     SET telegram_link_alerts=$1, telegram_system_alerts=$2
     WHERE id=$3`,
    [
      req.body.telegram_link_alerts === "on",
      allowSystemAlerts && req.body.telegram_system_alerts === "on",
      req.session.user.id,
    ]
  );
  req.session.telegramNotice = "Đã lưu loại thông báo Telegram.";
  return res.redirect("/account/telegram");
});

app.post("/account/telegram/test", checkAuth, async (req, res) => {
  const result = await db.query(
    `SELECT telegram_chat_id FROM users WHERE id=$1 LIMIT 1`,
    [req.session.user.id]
  );
  const chatId = result.rows[0]?.telegram_chat_id;
  if (!chatId) {
    req.session.telegramNotice = "Bạn chưa kết nối Telegram.";
    return res.redirect("/account/telegram");
  }
  try {
    await sendTelegramMessage(
      chatId,
      `✅ ${product.name}: kết nối Telegram đang hoạt động.\nBạn sẽ nhận cảnh báo riêng cho domain và link do tài khoản này tạo.`
    );
    req.session.telegramNotice = "Đã gửi thông báo thử nghiệm.";
  } catch (error) {
    req.session.telegramNotice = `Không gửi được Telegram: ${error.message}`;
  }
  return res.redirect("/account/telegram");
});

app.post("/account/telegram/disconnect", checkAuth, async (req, res) => {
  await db.query(
    `UPDATE users
     SET telegram_chat_id=NULL, telegram_username=NULL,
         telegram_connected_at=NULL, telegram_connect_code_hash=NULL,
         telegram_connect_expires_at=NULL
     WHERE id=$1`,
    [req.session.user.id]
  );
  await auditAdminAction({
    req,
    action: "telegram_disconnect",
    targetType: "user",
    targetId: req.session.user.id,
  });
  req.session.telegramNotice = "Đã ngắt kết nối Telegram.";
  return res.redirect("/account/telegram");
});

// --- LANDING ---
app.get("/", checkAuth, async (req, res) => {
  res.render("admin/welcome", { user: req.session.user });
});

// --- DASHBOARD ---
app.get("/redirect", checkAuth, async (req, res) => {
  const scopedUserId =
    req.session.user.role_name === "super_admin" ? null : req.session.user.id;
  const rDom = await db.query(
    `
      SELECT d.*, cu.username AS created_by_name, uu.username AS updated_by_name,
             (SELECT COUNT(*) FROM campaigns c WHERE c.domain_id = d.id) +
             (SELECT COUNT(*) FROM short_links s WHERE s.domain_id = d.id) AS link_count,
             (SELECT COUNT(*) FROM campaigns c WHERE c.domain_id = d.id AND c.is_active) +
             (SELECT COUNT(*) FROM short_links s WHERE s.domain_id = d.id AND s.is_active) AS link_active,
             (SELECT COUNT(*) FROM traffic_logs tl
              WHERE tl.domain_id = d.id
                AND tl.action IN ('redirect', 'short_redirect_confirmed')) AS traffic_count,
             (SELECT COUNT(*) FROM domain_user_access dua
              WHERE dua.domain_id=d.id) AS member_count
      FROM domains d
      LEFT JOIN users cu ON d.user_id = cu.id
      LEFT JOIN users uu ON d.updated_by = uu.id
      WHERE (
        $1::int IS NULL
        OR EXISTS (
          SELECT 1 FROM domain_user_access dua
          WHERE dua.domain_id=d.id AND dua.user_id=$1
        )
      )
      ORDER BY d.id DESC
    `,
    [scopedUserId]
  );
  const stats = await db.query(`
        SELECT (SELECT COUNT(*) FROM domains) AS total_domains_unscoped,
               (SELECT COUNT(*) FROM domains
                WHERE (
                  $1::int IS NULL
                  OR EXISTS (
                    SELECT 1 FROM domain_user_access dua
                    WHERE dua.domain_id=domains.id AND dua.user_id=$1
                  )
                )) as total_domains,
               (SELECT COUNT(*) FROM campaigns c
                WHERE (
                  $1::int IS NULL
                  OR EXISTS (
                    SELECT 1 FROM domain_user_access dua
                    WHERE dua.domain_id=c.domain_id AND dua.user_id=$1
                  )
                )) +
               (SELECT COUNT(*) FROM short_links s
                WHERE (
                  $1::int IS NULL
                  OR EXISTS (
                    SELECT 1 FROM domain_user_access dua
                    WHERE dua.domain_id=s.domain_id AND dua.user_id=$1
                  )
                )) as total_links,
               (SELECT COUNT(*) FROM traffic_logs
                 WHERE action IN ('redirect', 'short_redirect_confirmed')
                   AND ($1::int IS NULL OR domain_id IN
                     (SELECT domain_id FROM domain_user_access WHERE user_id=$1))) as total_traffic,
               (SELECT COUNT(*) FROM traffic_logs
                 WHERE action LIKE 'safe_page%'
                   AND ($1::int IS NULL OR domain_id IN
                     (SELECT domain_id FROM domain_user_access WHERE user_id=$1))) as total_safe_views,
               (SELECT COUNT(*) FROM traffic_logs
                 WHERE ($1::int IS NULL OR domain_id IN
                   (SELECT domain_id FROM domain_user_access WHERE user_id=$1))) as total_raw_requests
    `, [scopedUserId]);
  res.render("admin/dashboard", {
    user: req.session.user,
    domains: rDom.rows,
    stats: stats.rows[0],
  });
});

// --- SHORT LINKS ---
app.get("/short-links", checkAuth, async (req, res) => {
  return res.redirect("/redirect");
});

app.post("/short-links/create", checkAuth, ownDomainFromBody, async (req, res) => {
  const domainId = Number.parseInt(req.body.domain_id, 10);
  if (!Number.isInteger(domainId)) {
    const error = new Error("Domain khong hop le");
    notifyConfigError(req, "Tạo link tự động", error);
    return res.send(error.message);
  }

  try {
    const title = validateName(
      req.body.title || req.body.name || "Short link",
      "Ten link"
    );
    const targetUrl = normalizeTargetUrl(req.body.target_url);
    const redirectDelaySeconds = Number.parseInt(
      req.body.redirect_delay_seconds,
      10
    );
    if (
      !Number.isInteger(redirectDelaySeconds) ||
      redirectDelaySeconds < 1 ||
      redirectDelaySeconds > 30
    ) {
      throw new Error("Thoi gian cho phai tu 1 den 30 giay");
    }
    let code = req.body.code ? normalizeShortCode(req.body.code) : null;
    const domain = await db.query(`SELECT id FROM domains WHERE id=$1 LIMIT 1`, [
      domainId,
    ]);
    if (!domain.rowCount) throw new Error("Domain khong ton tai");

    for (let attempt = 0; attempt < 6; attempt += 1) {
      const currentCode = code || generateShortCode(attempt < 3 ? 7 : 9);
      try {
        await db.query(
          `
            INSERT INTO short_links
              (domain_id, user_id, code, title, target_url, updated_by, redirect_delay_seconds)
            VALUES ($1, $2, $3, $4, $5, $6, $7)
          `,
          [
            domainId,
            req.session.user.id,
            currentCode,
            title,
            targetUrl,
            req.session.user.id,
            redirectDelaySeconds,
          ]
        );
        await auditAdminAction({
          req,
          action: "short_link_create",
          targetType: "short_link",
          targetId: `${domainId}:${currentCode}`,
          detail: {
            domain_id: domainId,
            code: currentCode,
            title,
            redirect_delay_seconds: redirectDelaySeconds,
          },
        });
        return res.redirect(`/domains/${domainId}`);
      } catch (e) {
        if (e.code === "23505" && code) {
          throw new Error("Ma rut gon da ton tai tren domain nay");
        }
        if (e.code !== "23505") throw e;
      }
    }
    return res.send("Khong tao duoc ma rut gon, vui long thu lai");
  } catch (e) {
    notifyConfigError(req, "Tạo link tự động", e, [`Domain ID: ${domainId}`]);
    return res.send(e.message || "Link rut gon khong hop le");
  }
});

const toggleShortLinkHandler = async (req, res) => {
  const updated = await db.query(
    `UPDATE short_links SET is_active = NOT is_active, updated_by=$2 WHERE id=$1 RETURNING domain_id`,
    [req.params.id, req.session.user.id]
  );
  await auditAdminAction({
    req,
    action: "short_link_toggle",
    targetType: "short_link",
    targetId: req.params.id,
  });
  if (req.body.return_to_domain && updated.rowCount) {
    return res.redirect(`/domains/${updated.rows[0].domain_id}`);
  }
  return res.redirect("/short-links");
};

app.get("/short-links/toggle/:id", checkAuth, (req, res) =>
  res.status(405).send("Use POST /short-links/toggle/:id")
);
app.post("/short-links/toggle/:id", checkAuth, ownShortLinkFromParams, toggleShortLinkHandler);

const deleteShortLinkHandler = async (req, res) => {
  const deleted = await db.query(
    `DELETE FROM short_links WHERE id=$1 RETURNING domain_id`,
    [req.params.id]
  );
  await auditAdminAction({
    req,
    action: "short_link_delete",
    targetType: "short_link",
    targetId: req.params.id,
  });
  if (req.body.return_to_domain && deleted.rowCount) {
    return res.redirect(`/domains/${deleted.rows[0].domain_id}`);
  }
  return res.redirect("/short-links");
};
app.get("/short-links/delete/:id", checkAuth, ownShortLinkFromParams, (req, res) =>
  res.status(405).send("Use POST /short-links/delete/:id")
);
app.post(
  "/short-links/delete/:id",
  checkAuth,
  ownShortLinkFromParams,
  deleteShortLinkHandler
);

app.get("/short-links/:id/report", checkAuth, ownShortLinkFromParams, async (req, res) => {
  const shortLinkId = req.params.id;
  const preset = req.query.preset || "today";
  const now = new Date();
  const parseDate = (s) => {
    const d = new Date(s);
    return isNaN(d) ? null : d;
  };
  const startOfDay = (d) =>
    new Date(d.getFullYear(), d.getMonth(), d.getDate());
  const rangeLabelText = (s, e) => {
    const endDisplay = new Date(e);
    endDisplay.setDate(endDisplay.getDate() - 1);
    return `${s.toLocaleDateString("vi-VN")} - ${endDisplay.toLocaleDateString("vi-VN")}`;
  };
  const presetLabels = {
    today: "Hôm nay",
    this_week: "Tuần này",
    this_month: "Tháng này",
    this_year: "Năm nay",
    all: "Tất cả",
    custom: "Tùy chọn",
  };
  const bucketByPreset = {
    today: "hour",
    this_week: "day",
    this_month: "week",
    this_year: "month",
    all: "month",
    custom: "day",
  };

  const rLink = await db.query(
    `
      SELECT s.*, d.domain_url
      FROM short_links s
      JOIN domains d ON d.id = s.domain_id
      WHERE s.id=$1
    `,
    [shortLinkId]
  );
  if (!rLink.rowCount) return res.redirect("/short-links");
  const link = rLink.rows[0];

  let start;
  let end;
  let bucketType = bucketByPreset[preset] || "hour";
  if (preset === "this_week") {
    const today = startOfDay(now);
    const dow = today.getDay();
    const diff = dow === 0 ? -6 : 1 - dow;
    start = new Date(today);
    start.setDate(start.getDate() + diff);
    end = new Date(start);
    end.setDate(start.getDate() + 7);
  } else if (preset === "this_month") {
    start = new Date(now.getFullYear(), now.getMonth(), 1);
    end = new Date(now.getFullYear(), now.getMonth() + 1, 1);
  } else if (preset === "this_year") {
    start = new Date(now.getFullYear(), 0, 1);
    end = new Date(now.getFullYear() + 1, 0, 1);
  } else if (preset === "all") {
    const earliest = await db.query(
      `SELECT MIN(created_at) AS min_date FROM traffic_logs WHERE short_link_id=$1`,
      [shortLinkId]
    );
    const minRaw = earliest.rows[0]?.min_date || link.created_at || startOfDay(now);
    start = startOfDay(new Date(minRaw));
    end = startOfDay(now);
    end.setDate(end.getDate() + 1);
  } else if (preset === "custom") {
    const s = parseDate(req.query.start_date) || now;
    const e = parseDate(req.query.end_date) || s;
    start = startOfDay(s);
    end = startOfDay(e);
    end.setDate(end.getDate() + 1);
  } else {
    start = startOfDay(now);
    end = new Date(start);
    end.setDate(start.getDate() + 1);
    bucketType = "hour";
  }
  if (!end || end <= start) {
    end = new Date(start);
    end.setDate(start.getDate() + 1);
  }
  const rangeLabel = rangeLabelText(start, end);
  const diffMs = end.getTime() - start.getTime();
  const prevStart = new Date(start.getTime() - diffMs);
  const prevEnd = new Date(end.getTime() - diffMs);

  const stats = await db.query(
    `
      SELECT date_trunc($4::text, created_at) AS bucket,
             COUNT(*) FILTER (WHERE action='short_redirect_confirmed') AS confirmed
      FROM traffic_logs
      WHERE short_link_id=$1
        AND created_at >= $2
        AND created_at < $3
      GROUP BY bucket
      ORDER BY bucket ASC
    `,
    [shortLinkId, start, end, bucketType]
  );
  const totals = await db.query(
    `
      SELECT COUNT(*) FILTER (
               WHERE action IN ('short_link_open', 'short_redirect_confirmed')
             ) AS opened,
             COUNT(*) FILTER (WHERE action='short_redirect_confirmed') AS confirmed,
             COUNT(*) FILTER (WHERE action='short_link_open') AS unconfirmed,
             COUNT(DISTINCT ip) FILTER (
               WHERE action='short_redirect_confirmed'
             ) AS unique_ips
      FROM traffic_logs
      WHERE short_link_id=$1
        AND created_at >= $2
        AND created_at < $3
    `,
    [shortLinkId, start, end]
  );
  const prevTotals = await db.query(
    `
      SELECT COUNT(*) FILTER (
               WHERE action IN ('short_link_open', 'short_redirect_confirmed')
             ) AS opened,
             COUNT(*) FILTER (WHERE action='short_redirect_confirmed') AS confirmed,
             COUNT(*) FILTER (WHERE action='short_link_open') AS unconfirmed,
             COUNT(DISTINCT ip) FILTER (
               WHERE action='short_redirect_confirmed'
             ) AS unique_ips
      FROM traffic_logs
      WHERE short_link_id=$1
        AND created_at >= $2
        AND created_at < $3
    `,
    [shortLinkId, prevStart, prevEnd]
  );
  const lifetimeTotals = await db.query(
    `
      SELECT COUNT(*) FILTER (
               WHERE action IN ('short_link_open', 'short_redirect_confirmed')
             ) AS opened,
             COUNT(*) FILTER (WHERE action='short_redirect_confirmed') AS confirmed,
             COUNT(*) FILTER (WHERE action='short_link_open') AS unconfirmed,
             COUNT(DISTINCT ip) FILTER (
               WHERE action='short_redirect_confirmed'
             ) AS unique_ips,
             COUNT(*) FILTER (WHERE action='short_redirect') AS legacy_unverified
      FROM traffic_logs
      WHERE short_link_id=$1
    `,
    [shortLinkId]
  );
  const countryStats = await db.query(
    `
      SELECT country, COUNT(*) AS hits
      FROM traffic_logs
      WHERE short_link_id=$1
        AND created_at >= $2
        AND created_at < $3
        AND action='short_redirect_confirmed'
      GROUP BY country
      ORDER BY hits DESC
      LIMIT 10
    `,
    [shortLinkId, start, end]
  );
  const deviceStats = await db.query(
    `
      SELECT COALESCE(device_type, 'pc') AS device_type, COUNT(*) AS hits
      FROM traffic_logs
      WHERE short_link_id=$1
        AND created_at >= $2
        AND created_at < $3
        AND action='short_redirect_confirmed'
      GROUP BY COALESCE(device_type, 'pc')
      ORDER BY hits DESC
      LIMIT 10
    `,
    [shortLinkId, start, end]
  );
  const logs = await db.query(
    `
      SELECT *
      FROM traffic_logs
      WHERE short_link_id=$1
        AND created_at >= $2
        AND created_at < $3
      ORDER BY id DESC
      LIMIT 50
    `,
    [shortLinkId, start, end]
  );

  const summary = totals.rows[0] || {};
  summary.opened = Number(summary.opened || 0);
  summary.confirmed = Number(summary.confirmed || 0);
  summary.unconfirmed = Number(summary.unconfirmed || 0);
  summary.unique_ips = Number(summary.unique_ips || 0);
  const previous = prevTotals.rows[0] || {};
  previous.opened = Number(previous.opened || 0);
  previous.confirmed = Number(previous.confirmed || 0);
  previous.unconfirmed = Number(previous.unconfirmed || 0);
  previous.unique_ips = Number(previous.unique_ips || 0);
  const lifetime = lifetimeTotals.rows[0] || {};
  lifetime.opened = Number(lifetime.opened || 0);
  lifetime.confirmed = Number(lifetime.confirmed || 0);
  lifetime.unconfirmed = Number(lifetime.unconfirmed || 0);
  lifetime.unique_ips = Number(lifetime.unique_ips || 0);
  lifetime.legacy_unverified = Number(lifetime.legacy_unverified || 0);
  const delta = {
    opened: summary.opened - previous.opened,
    confirmed: summary.confirmed - previous.confirmed,
    unconfirmed: summary.unconfirmed - previous.unconfirmed,
    unique_ips: summary.unique_ips - previous.unique_ips,
  };

  res.render("admin/short_link_report", {
    user: req.session.user,
    link,
    stats: stats.rows,
    logs: logs.rows.map(parseLogMeta),
    summary,
    previous,
    lifetime,
    delta,
    countryStats: countryStats.rows,
    deviceStats: deviceStats.rows,
    preset,
    presetLabel: presetLabels[preset] || "Tùy chọn",
    bucketType,
    rangeLabel,
    start,
    end,
  });
});

app.get("/short-links/:id/logs", checkAuth, ownShortLinkFromParams, async (req, res) => {
  const shortLinkId = req.params.id;
  const limit = Math.min(parseInt(req.query.limit || "300", 10) || 300, 2000);
  const now = new Date();
  const start =
    req.query.start_date && !isNaN(new Date(req.query.start_date))
      ? new Date(req.query.start_date)
      : new Date(now.getTime() - 7 * 24 * 60 * 60 * 1000);
  const end =
    req.query.end_date && !isNaN(new Date(req.query.end_date))
      ? new Date(req.query.end_date)
      : now;
  const rLink = await db.query(
    `
      SELECT s.*, d.domain_url
      FROM short_links s
      JOIN domains d ON d.id = s.domain_id
      WHERE s.id=$1
    `,
    [shortLinkId]
  );
  if (!rLink.rowCount) return res.redirect("/short-links");
  const logs = await db.query(
    `
      SELECT *
      FROM traffic_logs
      WHERE short_link_id=$1
        AND created_at >= $2
        AND created_at < $3
      ORDER BY id DESC
      LIMIT ${limit}
    `,
    [shortLinkId, start, end]
  );
  res.render("admin/short_link_logs", {
    user: req.session.user,
    link: rLink.rows[0],
    logs: logs.rows.map(parseLogMeta),
    limit,
    start,
    end,
  });
});

app.get("/short-links/:id/report/export", checkAuth, ownShortLinkFromParams, async (req, res) => {
  const shortLinkId = req.params.id;
  const { normalized, start, end } = parseMonthRange(req.query.month);
  const rLink = await db.query(`SELECT title FROM short_links WHERE id=$1`, [
    shortLinkId,
  ]);
  if (!rLink.rowCount) return res.redirect("/short-links");

  const data = await db.query(
    `
      SELECT date(created_at) AS day,
             COUNT(*) FILTER (
               WHERE action IN ('short_link_open', 'short_redirect_confirmed')
             ) AS opened,
             COUNT(*) FILTER (WHERE action='short_redirect_confirmed') AS confirmed,
             COUNT(*) FILTER (WHERE action='short_link_open') AS unconfirmed,
             COUNT(DISTINCT ip) FILTER (
               WHERE action='short_redirect_confirmed'
             ) AS unique_ips
      FROM traffic_logs
      WHERE short_link_id=$1
        AND created_at >= $2
        AND created_at < $3
      GROUP BY day
      ORDER BY day ASC
    `,
    [shortLinkId, start, end]
  );

  const rows = ["day,opened,confirmed,unconfirmed,unique_ips"];
  data.rows.forEach((row) => {
    const day = new Date(row.day).toISOString().slice(0, 10);
    rows.push(
      `${day},${Number(row.opened || 0)},${Number(row.confirmed || 0)},${Number(row.unconfirmed || 0)},${Number(row.unique_ips || 0)}`
    );
  });

  res.setHeader("Content-Type", "text/csv");
  res.setHeader(
    "Content-Disposition",
    `attachment; filename=\"short-link-${shortLinkId}-${normalized}.csv\"`
  );
  res.send(rows.join("\n"));
});

// --- SAFE PAGE TEMPLATES ---
const requireAdvancedSafePages = (_req, res) =>
  res.status(410).send("Thư viện mẫu tùy chỉnh đã được thay bằng 2 mẫu cố định");

const safePagePayload = (body) => ({
  name: validateName(body.safe_page_name, "Tên mẫu"),
  template: normalizeAdvancedSafeTemplate(body.safe_page_template),
  content: normalizeSafeContent({
    title: body.safe_page_title,
    headline: body.safe_page_headline,
    logo: body.safe_page_logo,
    custom_html: body.safe_page_custom_html,
    custom_css: body.safe_page_custom_css,
  }),
});

app.get(
  "/safe-pages",
  checkAuth,
  requireAdvancedSafePages,
  async (req, res) => {
    const scopedUserId =
      req.session.user.role_name === "super_admin" ? null : req.session.user.id;
    const requestedDomainId = Number.parseInt(req.query.domain_id, 10);
    const selectedDomainId = Number.isInteger(requestedDomainId)
      ? requestedDomainId
      : null;
    const domains = await db.query(
      `SELECT id, domain_url, status
       FROM domains
       WHERE ($1::int IS NULL OR user_id=$1)
       ORDER BY domain_url`,
      [scopedUserId]
    );
    const safePages = await db.query(
      `SELECT sp.*, d.domain_url,
              cu.username AS created_by_name,
              uu.username AS updated_by_name,
              (SELECT COUNT(*) FROM campaigns c
               WHERE c.safe_page_id=sp.id) AS used_by_links
       FROM safe_pages sp
       JOIN domains d ON d.id=sp.domain_id
       LEFT JOIN users cu ON cu.id=sp.user_id
       LEFT JOIN users uu ON uu.id=sp.updated_by
       WHERE ($1::int IS NULL OR d.user_id=$1)
         AND ($2::int IS NULL OR sp.domain_id=$2)
       ORDER BY sp.id DESC`,
      [scopedUserId, selectedDomainId]
    );
    return res.render("admin/safe_pages", {
      user: req.session.user,
      domains: domains.rows,
      safePages: safePages.rows,
      selectedDomainId,
    });
  }
);

const createSafePageHandler = async (req, res) => {
  try {
    const domainId = Number.parseInt(
      req.body.domain_id || req.params.id,
      10
    );
    if (!Number.isInteger(domainId)) throw new Error("Domain không hợp lệ");
    const payload = safePagePayload(req.body);
    await db.query(
      `INSERT INTO safe_pages
         (domain_id, user_id, name, template, content, updated_by)
       VALUES ($1, $2, $3, $4, $5, $2)`,
      [
        domainId,
        req.session.user.id,
        payload.name,
        payload.template,
        JSON.stringify(payload.content),
      ]
    );
    await auditAdminAction({
      req,
      action: "safe_page_create",
      targetType: "safe_page",
      targetId: `${domainId}:${payload.name}`,
      detail: { domain_id: domainId, template: payload.template },
    });
    return res.redirect(`/safe-pages?domain_id=${domainId}`);
  } catch (error) {
    return res.status(400).send(error.message);
  }
};

app.post(
  "/safe-pages/create",
  checkAuth,
  requireAdvancedSafePages,
  ownDomainFromBody,
  createSafePageHandler
);
app.post(
  "/domains/:id/safe-pages/create",
  checkAuth,
  requireAdvancedSafePages,
  ownDomainFromParams,
  createSafePageHandler
);

app.post(
  "/safe-pages/update/:id",
  checkAuth,
  requireAdvancedSafePages,
  ownSafePageFromParams,
  async (req, res) => {
    try {
      const payload = safePagePayload(req.body);
      const result = await db.query(
        `UPDATE safe_pages
         SET name=$1, template=$2, content=$3, updated_by=$4
         WHERE id=$5
         RETURNING domain_id`,
        [
          payload.name,
          payload.template,
          JSON.stringify(payload.content),
          req.session.user.id,
          req.params.id,
        ]
      );
      await auditAdminAction({
        req,
        action: "safe_page_update",
        targetType: "safe_page",
        targetId: req.params.id,
        detail: { template: payload.template },
      });
      return res.redirect(
        result.rowCount
          ? `/safe-pages?domain_id=${result.rows[0].domain_id}`
          : "/safe-pages"
      );
    } catch (error) {
      return res.status(400).send(error.message);
    }
  }
);

app.post(
  "/safe-pages/toggle/:id",
  checkAuth,
  requireAdvancedSafePages,
  ownSafePageFromParams,
  async (req, res) => {
    const result = await db.query(
      `UPDATE safe_pages
       SET is_active=NOT is_active, updated_by=$2
       WHERE id=$1 RETURNING domain_id`,
      [req.params.id, req.session.user.id]
    );
    await auditAdminAction({
      req,
      action: "safe_page_toggle",
      targetType: "safe_page",
      targetId: req.params.id,
    });
    return res.redirect(
      result.rowCount
        ? `/safe-pages?domain_id=${result.rows[0].domain_id}`
        : "/safe-pages"
    );
  }
);

app.post(
  "/safe-pages/delete/:id",
  checkAuth,
  requireAdvancedSafePages,
  ownSafePageFromParams,
  async (req, res) => {
    const result = await db.query(
      `DELETE FROM safe_pages WHERE id=$1 RETURNING domain_id`,
      [req.params.id]
    );
    await auditAdminAction({
      req,
      action: "safe_page_delete",
      targetType: "safe_page",
      targetId: req.params.id,
    });
    return res.redirect(
      result.rowCount
        ? `/safe-pages?domain_id=${result.rows[0].domain_id}`
        : "/safe-pages"
    );
  }
);

// --- DOMAIN (CRUD) ---
app.post("/domains/create", checkAuth, async (req, res) => {
  try {
    const domainUrl = normalizeDomainUrl(req.body.domain_url);
    const safeTemplate = normalizeSafeTemplate(req.body.safe_template);
    const inserted = await db.query(
      `WITH created AS (
         INSERT INTO domains (domain_url, safe_template, user_id, updated_by, ssl_status)
         VALUES ($1, $2, $3, $4, $5)
         RETURNING id, user_id
       )
       INSERT INTO domain_user_access
         (domain_id, user_id, access_level, granted_by)
       SELECT id, user_id, 'owner', $4
       FROM created
       RETURNING domain_id AS id`,
      [
        domainUrl,
        safeTemplate,
        req.session.user.id,
        req.session.user.id,
        ssl.enabled ? "pending" : "fallback",
      ]
    );
    const domainId = inserted.rows[0].id;
    await auditAdminAction({
      req,
      action: "domain_create",
      targetType: "domain",
      targetId: domainId,
      detail: {
        domain_url: domainUrl,
        safe_template: safeTemplate,
        auto_ssl: ssl.enabled,
      },
    });
    queueDomainSsl(domainId);
    res.redirect(`/domains/${domainId}`);
  } catch (e) {
    notifyConfigError(req, "Thêm domain", e, [
      `Domain nhập vào: ${req.body.domain_url || "trống"}`,
    ]);
    res.send("Lỗi: Domain đã tồn tại");
  }
});

const parseUserIdList = (value) => {
  const values = Array.isArray(value) ? value : value ? [value] : [];
  return [
    ...new Set(
      values
        .map((item) => Number.parseInt(item, 10))
        .filter(Number.isInteger)
    ),
  ];
};

app.post(
  "/domains/:id/access",
  checkAuth,
  requireRole(["super_admin"]),
  async (req, res) => {
    const domainId = Number.parseInt(req.params.id, 10);
    const ownerUserId = Number.parseInt(req.body.owner_user_id, 10);
    if (!Number.isInteger(domainId) || !Number.isInteger(ownerUserId)) {
      return res.status(400).send("Domain hoặc chủ sở hữu không hợp lệ");
    }

    const memberUserIds = parseUserIdList(req.body.member_user_ids);
    const selectedUserIds = [...new Set([ownerUserId, ...memberUserIds])];
    const users = await db.query(
      `SELECT id
       FROM users
       WHERE is_active=true AND id=ANY($1::int[])
       ORDER BY id`,
      [selectedUserIds]
    );
    if (users.rowCount !== selectedUserIds.length) {
      return res.status(400).send("Danh sách người dùng có tài khoản không hợp lệ");
    }

    const client = await db.connect();
    try {
      await client.query("BEGIN");
      const domain = await client.query(
        `UPDATE domains
         SET user_id=$2, updated_by=$3, updated_at=now()
         WHERE id=$1
         RETURNING id, domain_url`,
        [domainId, ownerUserId, req.session.user.id]
      );
      if (!domain.rowCount) {
        await client.query("ROLLBACK");
        return res.status(404).send("Không tìm thấy domain");
      }

      await client.query(`DELETE FROM domain_user_access WHERE domain_id=$1`, [
        domainId,
      ]);
      await client.query(
        `INSERT INTO domain_user_access
           (domain_id, user_id, access_level, granted_by)
         SELECT $1, member_id,
                CASE WHEN member_id=$2 THEN 'owner' ELSE 'member' END,
                $3
         FROM unnest($4::int[]) AS member_id`,
        [domainId, ownerUserId, req.session.user.id, selectedUserIds]
      );
      await client.query("COMMIT");

      await auditAdminAction({
        req,
        action: "domain_access_update",
        targetType: "domain",
        targetId: domainId,
        detail: {
          domain_url: domain.rows[0].domain_url,
          owner_user_id: ownerUserId,
          member_user_ids: selectedUserIds,
        },
      });
      return res.redirect(`/domains/${domainId}`);
    } catch (error) {
      await client.query("ROLLBACK").catch(() => undefined);
      notifyConfigError(req, "Cập nhật quyền domain", error, [
        `Domain ID: ${domainId}`,
      ]);
      return res.status(500).send("Không thể cập nhật quyền domain");
    } finally {
      client.release();
    }
  }
);

const toggleDomainHandler = async (req, res) => {
  await db.query(
    `UPDATE domains SET status = CASE WHEN status='active' THEN 'inactive' ELSE 'active' END, updated_by=$2 WHERE id=$1`,
    [req.params.id, req.session.user.id]
  );
  await auditAdminAction({
    req,
    action: "domain_toggle",
    targetType: "domain",
    targetId: req.params.id,
  });
  res.redirect("/redirect");
};
app.get("/domains/toggle/:id", checkAuth, (req, res) =>
  res.status(405).send("Use POST /domains/toggle/:id")
);
app.post("/domains/toggle/:id", checkAuth, ownDomainFromParams, toggleDomainHandler);

app.post("/domains/:id/ssl/retry", checkAuth, ownDomainFromParams, async (req, res) => {
  if (!ssl.enabled) {
    return res.status(503).send("Automatic SSL is not enabled on this server");
  }
  const result = await db.query(
    `UPDATE domains
     SET ssl_status='pending', ssl_error=NULL, ssl_attempts=0, ssl_updated_at=now()
     WHERE id=$1
     RETURNING id`,
    [req.params.id]
  );
  if (!result.rowCount) return res.status(404).send("Domain not found");
  await auditAdminAction({
    req,
    action: "domain_ssl_retry",
    targetType: "domain",
    targetId: req.params.id,
  });
  queueDomainSsl(result.rows[0].id, { force: true });
  return res.redirect(`/domains/${result.rows[0].id}`);
});

// Chỉ super admin được xóa domain.
const deleteDomainHandler = async (req, res) => {
  try {
    await db.query(`DELETE FROM domains WHERE id=$1`, [req.params.id]);
    await auditAdminAction({
      req,
      action: "domain_delete",
      targetType: "domain",
      targetId: req.params.id,
    });
    res.redirect("/redirect");
  } catch (e) {
    res.send("Lỗi khi xóa domain: " + e.message);
  }
};
app.get("/domains/delete/:id", checkAuth, ownDomainFromParams, (req, res) =>
  res.status(405).send("Use POST /domains/delete/:id")
);
app.post(
  "/domains/delete/:id",
  checkAuth,
  requireRole(["super_admin"]),
  deleteDomainHandler
);

const verifyDomainHandler = async (req, res) => {
  const r = await db.query(`SELECT domain_url FROM domains WHERE id=$1`, [
    req.params.id,
  ]);
  if (!r.rowCount) return res.json({ status: "error" });
  dns.resolve4(r.rows[0].domain_url, async (err, addrs) => {
    if (err) {
      notifyConfigError(req, "Kiểm tra DNS domain", err, [
        `Domain: ${r.rows[0].domain_url}`,
      ]);
      await auditAdminAction({
        req,
        action: "domain_verify",
        targetType: "domain",
        targetId: req.params.id,
        status: "failed",
        detail: { error: err.message },
      });
      return res.json({ status: "error", msg: "DNS chưa trỏ về máy chủ" });
    }
    await db.query(`UPDATE domains SET status='active', updated_by=$2 WHERE id=$1`, [
      req.params.id,
      req.session.user.id,
    ]);
    queueDomainSsl(req.params.id);
    await auditAdminAction({
      req,
      action: "domain_verify",
      targetType: "domain",
      targetId: req.params.id,
      detail: { address: addrs[0] },
    });
    res.json({ status: "success", msg: "OK: " + addrs[0] });
  });
};
app.get("/domains/:id/verify", checkAuth, ownDomainFromParams, verifyDomainHandler);
app.post("/domains/:id/verify", checkAuth, ownDomainFromParams, verifyDomainHandler);

// --- LINK CAMPAIGNS ---
app.get("/domains/:id/safe-preview", checkAuth, ownDomainFromParams, async (req, res) => {
  const result = await db.query(
    `SELECT domain_url, safe_template FROM domains WHERE id=$1 LIMIT 1`,
    [req.params.id]
  );
  if (!result.rowCount) return res.status(404).send("Domain not found");

  const domain = result.rows[0];
  const template = normalizeSafeTemplate(domain.safe_template || "clean");
  return res.render(`safepages/${template}`, {
    title: domain.domain_url,
    domain: domain.domain_url,
  });
});

app.get("/domains/:id", checkAuth, ownDomainFromParams, async (req, res) => {
  const domainId = req.params.id;
  const rDom = await db.query(
    `
      SELECT d.*, cu.username AS owner_name, uu.username AS updated_by_name
      FROM domains d
      LEFT JOIN users cu ON d.user_id = cu.id
      LEFT JOIN users uu ON d.updated_by = uu.id
      WHERE d.id=$1
    `,
    [domainId]
  );
  if (!rDom.rowCount) return res.redirect("/redirect");

  const domainMembers = await db.query(
    `SELECT u.id, u.username, r.name AS role_name, dua.access_level
     FROM domain_user_access dua
     JOIN users u ON u.id=dua.user_id
     JOIN roles r ON r.id=u.role_id
     WHERE dua.domain_id=$1
     ORDER BY CASE WHEN dua.access_level='owner' THEN 0 ELSE 1 END, u.username`,
    [domainId]
  );
  const assignableUsers =
    req.session.user.role_name === "super_admin"
      ? await db.query(
          `SELECT u.id, u.username, r.name AS role_name
           FROM users u
           JOIN roles r ON r.id=u.role_id
           WHERE u.is_active=true
           ORDER BY CASE WHEN r.name='super_admin' THEN 0 ELSE 1 END, u.username`
        )
      : { rows: [] };

  const rLinks = await db.query(
    `
      SELECT c.*, cu.username AS created_by_name, uu.username AS updated_by_name,
             (SELECT COUNT(*) FROM traffic_logs tl
              WHERE tl.campaign_id=c.id AND tl.action='redirect') AS log_redirects
      FROM campaigns c
      LEFT JOIN users cu ON c.user_id = cu.id
      LEFT JOIN users uu ON c.updated_by = uu.id
      WHERE c.domain_id=$1
      ORDER BY c.id DESC
    `,
    [domainId]
  );

  const rShortLinks = await db.query(
    `
      SELECT s.*, cu.username AS created_by_name, uu.username AS updated_by_name,
             (SELECT COUNT(*) FROM traffic_logs tl
               WHERE tl.short_link_id=s.id AND tl.action='short_redirect_confirmed') AS confirmed_redirects,
             (SELECT COUNT(*) FROM traffic_logs tl
               WHERE tl.short_link_id=s.id
                 AND tl.action IN ('short_link_open', 'short_redirect_confirmed')) AS opened_count
      FROM short_links s
      LEFT JOIN users cu ON s.user_id = cu.id
      LEFT JOIN users uu ON s.updated_by = uu.id
      WHERE s.domain_id=$1
      ORDER BY s.id DESC
    `,
    [domainId]
  );

  const linkStats = await db.query(
    `
      SELECT
        (SELECT COUNT(*) FROM campaigns WHERE domain_id=$1) +
        (SELECT COUNT(*) FROM short_links WHERE domain_id=$1) AS total,
        (SELECT COUNT(*) FROM campaigns WHERE domain_id=$1 AND is_active) +
        (SELECT COUNT(*) FROM short_links WHERE domain_id=$1 AND is_active) AS active
    `,
    [domainId]
  );

  const domainTrafficStats = await db.query(
    `
      SELECT
        COUNT(*) FILTER (
          WHERE action IN ('redirect', 'short_redirect_confirmed')
        ) AS link_traffic,
        COUNT(*) FILTER (WHERE action LIKE 'safe_page%') AS safe_page_views,
        COUNT(*) FILTER (
          WHERE campaign_id IS NULL AND short_link_id IS NULL
        ) AS direct_or_unmatched
      FROM traffic_logs
      WHERE domain_id=$1
    `,
    [domainId]
  );

  const links = rLinks.rows.map((l) => {
    const key = l.param_key || "q";
    const val = l.param_value || l.id;
    l.full_url = `https://${rDom.rows[0].domain_url}/?${key}=${val}`;
    l.potential_traffic = 0;
    return l;
  });
  const shortLinks = rShortLinks.rows.map((link) => ({
    ...link,
    full_url: `https://${rDom.rows[0].domain_url}/s/${link.code}`,
  }));

  // Đếm lượt hiển thị Safe Page theo link để đưa ra gợi ý vận hành.
  const linkIds = links.map((l) => l.id);
  if (linkIds.length) {
    const safeMap = new Map();
    const safeRows = await db.query(
      `
        SELECT campaign_id,
               COUNT(*) FILTER (WHERE action LIKE 'safe_page%') AS safe_total,
               COUNT(*) FILTER (WHERE action LIKE 'safe_page%' AND created_at >= now() - interval '24 hours') AS safe_24h
        FROM traffic_logs
        WHERE campaign_id = ANY($1)
        GROUP BY campaign_id
      `,
      [linkIds]
    );
    safeRows.rows.forEach((row) => safeMap.set(row.campaign_id, row));
    for (let l of links) {
      const safe = safeMap.get(l.id) || {};
      l.safe_total = Number(safe.safe_total || 0);
      l.safe_24h = Number(safe.safe_24h || 0);
      l.suggestion = !l.is_active && l.safe_24h >= 20;
    }
  }

  res.render("admin/domain_detail", {
    user: req.session.user,
    domain: rDom.rows[0],
    links,
    shortLinks,
    linkStats: linkStats.rows[0],
    domainTrafficStats: domainTrafficStats.rows[0],
    domainMembers: domainMembers.rows,
    assignableUsers: assignableUsers.rows,
  });
});

app.get("/domains/:id/safe-content", checkAuth, requireAdvancedSafePages);
app.post(
  "/domains/:id/safe-content",
  checkAuth,
  requireAdvancedSafePages,
  ownDomainFromParams,
  async (req, res) => {
    const template = normalizeAdvancedSafeTemplate(req.body.safe_template);
    const content = normalizeSafeContent({
      title: req.body.safe_title,
      headline: req.body.safe_headline,
      logo: req.body.safe_logo,
      custom_html: req.body.safe_custom_html,
      custom_css: req.body.safe_custom_css,
    });
    await db.query(
      `UPDATE domains
       SET safe_template=$1, safe_content=$2, updated_by=$3
       WHERE id=$4`,
      [
        template,
        JSON.stringify(content),
        req.session.user.id,
        req.params.id,
      ]
    );
    await auditAdminAction({
      req,
      action: "domain_safe_content_update",
      targetType: "domain",
      targetId: req.params.id,
      detail: { safe_template: template },
    });
    return res.redirect(`/domains/${req.params.id}`);
  }
);

app.post("/campaigns/create", checkAuth, ownDomainFromBody, async (req, res) => {
  const {
    domain_id,
    name,
    target_url,
    rules_json,
    allowed_countries,
    copy_from_id,
  } = req.body;
  try {
    const normalizedDomainId = Number.parseInt(domain_id, 10);
    if (!Number.isInteger(normalizedDomainId))
      throw new Error("Domain khong hop le");
    const normalizedName = validateName(name, "Ten link");
    const normalizedTargetUrl = normalizeTargetUrl(target_url);
    let rulesPayload = parseRules(rules_json);
    let rulesPayloadJson = JSON.stringify(rulesPayload || []);
    let normalizedSafePageId = null;
    if (normalizedSafePageId && !Number.isInteger(normalizedSafePageId)) {
      throw new Error("Mẫu Safe Page không hợp lệ");
    }
    const dup = await db.query(
      `SELECT 1 FROM campaigns WHERE domain_id=$1 AND LOWER(name)=LOWER($2) LIMIT 1`,
      [normalizedDomainId, normalizedName]
    );
    if (dup.rowCount) throw new Error("Ten link bi trung trong domain");

    let filters = buildFilters(allowed_countries);

    if (copy_from_id && rulesPayload.length === 0 && !allowed_countries) {
      const rCfg = await db.query(
        `SELECT rules, filters FROM campaigns WHERE id=$1 AND domain_id=$2`,
        [copy_from_id, normalizedDomainId]
      );
      if (rCfg.rowCount) {
        rulesPayload = parseRules(rCfg.rows[0].rules || []);
        filters = buildFilters(rCfg.rows[0].filters?.countries || []);
        rulesPayloadJson = JSON.stringify(rulesPayload || []);
      }
    }
    if (normalizedSafePageId) {
      const safePage = await db.query(
        `SELECT id FROM safe_pages
         WHERE id=$1 AND domain_id=$2 AND is_active=true LIMIT 1`,
        [normalizedSafePageId, normalizedDomainId]
      );
      if (!safePage.rowCount) throw new Error("Mẫu Safe Page không hợp lệ");
    }
    const filtersJson = JSON.stringify(filters || {});

    const autoKey = validateParamKey("q");
    const autoValue = validateParamValue(generateCode(8));

    await db.query(
      `
            INSERT INTO campaigns
              (domain_id, user_id, name, param_key, param_value,
               target_url, rules, filters, updated_by)
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
        `,
      [
        normalizedDomainId,
        req.session.user.id,
        normalizedName,
        autoKey,
        autoValue,
        normalizedTargetUrl,
        rulesPayloadJson,
        filtersJson,
        req.session.user.id,
      ]
    );

    await auditAdminAction({
      req,
      action: "campaign_create",
      targetType: "campaign",
      targetId: `${normalizedDomainId}:${normalizedName}`,
      detail: {
        domain_id: normalizedDomainId,
        name: normalizedName,
      },
    });
    res.redirect("/domains/" + normalizedDomainId);
  } catch (e) {
    notifyConfigError(req, "Tạo link điều kiện", e, [
      `Domain ID: ${domain_id || "trống"}`,
      `Tên link: ${name || "trống"}`,
    ]);
    res.send(e.message);
  }
});

const toggleCampaignHandler = async (req, res) => {
  await db.query(
    `UPDATE campaigns SET is_active = NOT is_active, updated_by=$2 WHERE id=$1`,
    [req.params.id, req.session.user.id]
  );
  await auditAdminAction({
    req,
    action: "campaign_toggle",
    targetType: "campaign",
    targetId: req.params.id,
  });
  const r = await db.query(`SELECT domain_id FROM campaigns WHERE id=$1`, [
    req.params.id,
  ]);
  res.redirect("/domains/" + r.rows[0].domain_id);
};
app.get("/campaigns/toggle/:id", checkAuth, (req, res) =>
  res.status(405).send("Use POST /campaigns/toggle/:id")
);
app.post(
  "/campaigns/toggle/:id",
  checkAuth,
  ownCampaignFromParams,
  toggleCampaignHandler
);

// Chỉ super admin được xóa link.
const deleteCampaignHandler = async (req, res) => {
  const r = await db.query(`SELECT domain_id FROM campaigns WHERE id=$1`, [
    req.params.id,
  ]);
  if (r.rowCount) {
    await db.query(`DELETE FROM traffic_logs WHERE campaign_id=$1`, [
      req.params.id,
    ]);
    await db.query(`DELETE FROM campaigns WHERE id=$1`, [req.params.id]);
    await auditAdminAction({
      req,
      action: "campaign_delete",
      targetType: "campaign",
      targetId: req.params.id,
      detail: { domain_id: r.rows[0].domain_id },
    });
    res.redirect("/domains/" + r.rows[0].domain_id);
  } else {
    res.redirect("/redirect");
  }
};
app.get(
  "/campaigns/delete/:id",
  checkAuth,
  ownCampaignFromParams,
  (req, res) => res.status(405).send("Use POST /campaigns/delete/:id")
);
app.post(
  "/campaigns/delete/:id",
  checkAuth,
  ownCampaignFromParams,
  deleteCampaignHandler
);

app.get("/campaigns/edit/:id", checkAuth, ownCampaignFromParams, async (req, res) => {
  const r = await db.query(
    `SELECT c.*, cu.username AS created_by_name, uu.username AS updated_by_name
     FROM campaigns c
     LEFT JOIN users cu ON c.user_id = cu.id
     LEFT JOIN users uu ON c.updated_by = uu.id
     WHERE c.id=$1`,
    [req.params.id]
  );
  if (!r.rowCount) return res.redirect("/redirect");
  const d = await db.query(`SELECT * FROM domains WHERE id=$1`, [
    r.rows[0].domain_id,
  ]);
  const others = await db.query(
    `SELECT id, name FROM campaigns WHERE domain_id=$1 ORDER BY id DESC`,
    [r.rows[0].domain_id]
  );
  res.render("admin/campaign_edit", {
    user: req.session.user,
    camp: r.rows[0],
    domain: d.rows[0],
    otherCamps: others.rows.filter((c) => c.id !== r.rows[0].id),
  });
});

app.post("/campaigns/update/:id", checkAuth, ownCampaignFromParams, async (req, res) => {
  const {
    name,
    target_url,
    rules_json,
    allowed_countries,
    domain_id,
  } =
    req.body;
  try {
    const normalizedDomainId = Number.parseInt(domain_id, 10);
    if (!Number.isInteger(normalizedDomainId))
      throw new Error("Domain khong hop le");
    const normalizedName = validateName(name, "Ten link");
    const normalizedTargetUrl = normalizeTargetUrl(target_url);
    const rulesPayload = parseRules(rules_json);
    const filters = buildFilters(allowed_countries);
    const rulesPayloadJson = JSON.stringify(rulesPayload || []);
    const filtersJson = JSON.stringify(filters || {});
    const normalizedSafePageId = null;
    if (normalizedSafePageId) {
      const safePage = await db.query(
        `SELECT id FROM safe_pages
         WHERE id=$1 AND domain_id=$2 AND is_active=true LIMIT 1`,
        [normalizedSafePageId, normalizedDomainId]
      );
      if (!safePage.rowCount) throw new Error("Mẫu Safe Page không hợp lệ");
    }
    const dup = await db.query(
      `SELECT 1 FROM campaigns WHERE domain_id=$1 AND LOWER(name)=LOWER($2) AND id<>$3 LIMIT 1`,
      [normalizedDomainId, normalizedName, req.params.id]
    );
    if (dup.rowCount) throw new Error("Ten link bi trung trong domain");

    await db.query(
      `UPDATE campaigns
       SET name=$1, target_url=$2, rules=$3, filters=$4,
           safe_page_id=NULL, safe_template_override=NULL, updated_by=$5
       WHERE id=$6`,
      [
        normalizedName,
        normalizedTargetUrl,
        rulesPayloadJson,
        filtersJson,
        req.session.user.id,
        req.params.id,
      ]
    );
    await auditAdminAction({
      req,
      action: "campaign_update",
      targetType: "campaign",
      targetId: req.params.id,
      detail: { domain_id: normalizedDomainId, name: normalizedName },
    });
    res.redirect("/domains/" + normalizedDomainId);
  } catch (e) {
    notifyConfigError(req, "Cập nhật link điều kiện", e, [
      `Link ID: ${req.params.id}`,
      `Tên link: ${name || "trống"}`,
    ]);
    return res.send(e.message || "Rules khong hop le");
  }
});

app.get("/api/campaigns/:id/config", checkAuth, ownCampaignFromParams, async (req, res) => {
  const campId = req.params.id;
  const r = await db.query(
    `SELECT id, name, rules, filters, param_key, param_value
     FROM campaigns WHERE id=$1`,
    [campId]
  );
  if (!r.rowCount) return res.status(404).json({ error: "not_found" });
  const row = r.rows[0];
  res.json({
    id: row.id,
    name: row.name,
    rules: row.rules || [],
    filters: row.filters || {},
    param_key: row.param_key,
    param_value: row.param_value,
  });
});

// ... 기존 routes ...
app.get("/campaigns/:id/report/v2", checkAuth, ownCampaignFromParams, async (req, res) => {
  const campId = req.params.id;
  const preset = req.query.preset || "today"; // today/this_week/this_month/this_year/all/custom
  const now = new Date();

  const parseDate = (s) => {
    const d = new Date(s);
    return isNaN(d) ? null : d;
  };
  const startOfDay = (d) =>
    new Date(d.getFullYear(), d.getMonth(), d.getDate());
  const rangeLabelText = (s, e) => {
    const endDisplay = new Date(e);
    endDisplay.setDate(endDisplay.getDate() - 1);
    return `${s.toLocaleDateString("vi-VN")} - ${endDisplay.toLocaleDateString("vi-VN")}`;
  };
  const presetLabels = {
    today: "Hôm nay",
    this_week: "Tuần này",
    this_month: "Tháng này",
    this_year: "Năm nay",
    all: "Tất cả",
    custom: "Tùy chọn",
  };

  const bucketByPreset = {
    today: "hour",
    this_week: "day",
    this_month: "week",
    this_year: "month",
    all: "month",
    custom: "day",
  };

  const rCamp = await db.query(`SELECT * FROM campaigns WHERE id=$1`, [
    campId,
  ]);
  if (!rCamp.rowCount) return res.redirect("/redirect");
  const camp = rCamp.rows[0];

  let start;
  let end;
  let bucketType = bucketByPreset[preset] || "hour";

  if (preset === "this_week") {
    const today = startOfDay(now);
    const dow = today.getDay();
    const diff = dow === 0 ? -6 : 1 - dow; // Monday start
    start = new Date(today);
    start.setDate(start.getDate() + diff);
    end = new Date(start);
    end.setDate(start.getDate() + 7);
  } else if (preset === "this_month") {
    start = new Date(now.getFullYear(), now.getMonth(), 1);
    end = new Date(now.getFullYear(), now.getMonth() + 1, 1);
  } else if (preset === "this_year") {
    start = new Date(now.getFullYear(), 0, 1);
    end = new Date(now.getFullYear() + 1, 0, 1);
  } else if (preset === "all") {
    const earliest = await db.query(
      `SELECT MIN(created_at) AS min_date FROM traffic_logs WHERE campaign_id=$1`,
      [campId]
    );
    const minRaw =
      earliest.rows[0]?.min_date || camp.created_at || startOfDay(now);
    const minDate = new Date(minRaw);
    start = startOfDay(minDate);
    end = startOfDay(now);
    end.setDate(end.getDate() + 1);
  } else if (preset === "custom") {
    const s = parseDate(req.query.start_date) || now;
    const e = parseDate(req.query.end_date) || s;
    start = startOfDay(s);
    end = startOfDay(e);
    end.setDate(end.getDate() + 1);
  } else {
    start = startOfDay(now);
    end = new Date(start);
    end.setDate(start.getDate() + 1);
    bucketType = "hour";
  }

  if (!end || end <= start) {
    end = new Date(start);
    end.setDate(start.getDate() + 1);
  }
  const rangeLabel = rangeLabelText(start, end);

  const diffMs = end.getTime() - start.getTime();
  const prevStart = new Date(start.getTime() - diffMs);
  const prevEnd = new Date(end.getTime() - diffMs);

  const stats = await db.query(
    `
        SELECT date_trunc($4::text, created_at) as bucket,
               COUNT(*) FILTER (WHERE action = 'redirect') as redirects,
               COUNT(*) FILTER (WHERE action LIKE 'safe_page%') as safe
        FROM traffic_logs
        WHERE campaign_id = $1
          AND created_at >= $2
          AND created_at < $3
        GROUP BY bucket
        ORDER BY bucket ASC
      `,
    [campId, start, end, bucketType]
  );

  const totals = await db.query(
    `
        SELECT COUNT(*) FILTER (WHERE action = 'redirect') as redirects,
               COUNT(*) FILTER (WHERE action LIKE 'safe_page%') as safe,
               COUNT(*) as total
        FROM traffic_logs
        WHERE campaign_id = $1
          AND created_at >= $2
          AND created_at < $3
      `,
    [campId, start, end]
  );

  const prevTotals = await db.query(
    `
        SELECT COUNT(*) FILTER (WHERE action = 'redirect') as redirects,
               COUNT(*) FILTER (WHERE action LIKE 'safe_page%') as safe,
               COUNT(*) as total
        FROM traffic_logs
        WHERE campaign_id = $1
          AND created_at >= $2
          AND created_at < $3
      `,
    [campId, prevStart, prevEnd]
  );

  const countryStats = await db.query(
    `
        SELECT country,
               COUNT(*) FILTER (WHERE action='redirect') as redirects,
               COUNT(*) as hits
        FROM traffic_logs
        WHERE campaign_id=$1
          AND created_at >= $2
          AND created_at < $3
        GROUP BY country
        ORDER BY hits DESC
        LIMIT 10
    `,
    [campId, start, end]
  );

  const deviceStats = await db.query(
    `
        SELECT COALESCE(device_type, 'pc') AS device_type,
               COUNT(*) AS hits
        FROM traffic_logs
        WHERE campaign_id=$1
          AND created_at >= $2
          AND created_at < $3
          AND action='redirect'
        GROUP BY COALESCE(device_type, 'pc')
        ORDER BY hits DESC
        LIMIT 10
    `,
    [campId, start, end]
  );

  const logs = await db.query(
    `SELECT * FROM traffic_logs WHERE campaign_id=$1 AND created_at >= $2 AND created_at < $3 ORDER BY id DESC LIMIT 50`,
    [campId, start, end]
  );

  const summary = totals.rows[0] || { redirects: 0, safe: 0, total: 0 };
  summary.redirects = Number(summary.redirects || 0);
  summary.safe = Number(summary.safe || 0);
  summary.total = Number(summary.total || 0);
  summary.fail = summary.safe;
  summary.pass_rate =
    summary.total > 0
      ? Math.round((summary.redirects / summary.total) * 1000) / 10
      : 0;

  const previous = prevTotals.rows[0] || { redirects: 0, safe: 0, total: 0 };
  previous.redirects = Number(previous.redirects || 0);
  previous.safe = Number(previous.safe || 0);
  previous.total = Number(previous.total || 0);
  previous.pass_rate =
    previous.total > 0
      ? Math.round((previous.redirects / previous.total) * 1000) / 10
      : 0;

  const delta = {
    redirects: summary.redirects - previous.redirects,
    safe: summary.safe - previous.safe,
    pass_rate: summary.pass_rate - previous.pass_rate,
  };
  const growth = {
    redirects:
      previous.redirects > 0
        ? Math.round((delta.redirects / previous.redirects) * 1000) / 10
        : null,
    safe:
      previous.safe > 0
        ? Math.round((delta.safe / previous.safe) * 1000) / 10
        : null,
    pass_rate:
      previous.pass_rate !== null
        ? Math.round(delta.pass_rate * 10) / 10
        : null,
  };

  res.render("admin/report_v2", {
    user: req.session.user,
    camp,
    stats: stats.rows,
    logs: logs.rows.map(parseLogMeta),
    summary,
    previous,
    delta,
    growth,
    countryStats: countryStats.rows,
    deviceStats: deviceStats.rows,
    preset,
    presetLabel: presetLabels[preset] || "Tùy chọn",
    bucketType,
    rangeLabel,
    start,
    end,
  });
});
app.get("/campaigns/:id/report", checkAuth, ownCampaignFromParams, async (req, res) => {
  const campId = req.params.id;
  const query = req.originalUrl.includes("?")
    ? req.originalUrl.slice(req.originalUrl.indexOf("?"))
    : "";
  return res.redirect(`/campaigns/${campId}/report/v2${query}`);
});

app.get("/campaigns/:id/logs", checkAuth, ownCampaignFromParams, async (req, res) => {
  const campId = req.params.id;
  const action = req.query.action;
  const limit = Math.min(parseInt(req.query.limit || "300", 10) || 300, 2000);
  const now = new Date();
  const start =
    req.query.start_date && !isNaN(new Date(req.query.start_date))
      ? new Date(req.query.start_date)
      : new Date(now.getTime() - 7 * 24 * 60 * 60 * 1000);
  const end =
    req.query.end_date && !isNaN(new Date(req.query.end_date))
      ? new Date(req.query.end_date)
      : now;
  const rCamp = await db.query(`SELECT * FROM campaigns WHERE id=$1`, [
    campId,
  ]);
  if (!rCamp.rowCount) return res.redirect("/redirect");
  let sql = `SELECT * FROM traffic_logs WHERE campaign_id=$1 AND created_at >= $2 AND created_at < $3`;
  const params = [campId, start, end];
  if (action) {
    params.push(action);
    sql += ` AND action=$${params.length}`;
  }
  sql += ` ORDER BY id DESC LIMIT ${limit}`;
  const logs = await db.query(sql, params);
  const logsMapped = logs.rows.map(parseLogMeta);
  res.render("admin/logs", {
    user: req.session.user,
    camp: rCamp.rows[0],
    logs: logsMapped,
    action,
    limit,
    start,
    end,
  });
});

app.get("/campaigns/:id/report/export", checkAuth, ownCampaignFromParams, async (req, res) => {
  const campId = req.params.id;
  const { normalized, start, end } = parseMonthRange(req.query.month);
  const rCamp = await db.query(`SELECT name FROM campaigns WHERE id=$1`, [
    campId,
  ]);
  if (!rCamp.rowCount) return res.redirect("/redirect");

  const data = await db.query(
    `
      SELECT date(created_at) as day,
             COUNT(*) FILTER (WHERE action='redirect') as redirects,
             COUNT(*) FILTER (WHERE action LIKE 'safe_page%') as safe
      FROM traffic_logs
      WHERE campaign_id=$1
        AND created_at >= $2
        AND created_at < $3
      GROUP BY day
      ORDER BY day ASC
    `,
    [campId, start, end]
  );

  const rows = ["day,redirects,safe,total,pass_rate_percent"];
  data.rows.forEach((row) => {
    const day = new Date(row.day).toISOString().slice(0, 10);
    const redirects = Number(row.redirects || 0);
    const safe = Number(row.safe || 0);
    const total = redirects + safe;
    const rate = total ? Math.round((redirects / total) * 1000) / 10 : 0;
    rows.push(`${day},${redirects},${safe},${total},${rate}`);
  });

  res.setHeader("Content-Type", "text/csv");
  res.setHeader(
    "Content-Disposition",
    `attachment; filename=\"campaign-${campId}-${normalized}.csv\"`
  );
  res.send(rows.join("\n"));
});
// ...

// --- QUẢN TRỊ NGƯỜI DÙNG ---
// Chỉ super admin được xem và quản lý danh sách tài khoản.
app.get("/users", requireRole(["super_admin"]), async (req, res) => {
  const currentUserRole = req.session.user.role_name;
  const u = await db.query(
    `SELECT u.id, u.username, u.is_active, u.created_at, r.name as role_name
     FROM users u LEFT JOIN roles r ON u.role_id = r.id ORDER BY u.id ASC`
  );

  res.render("admin/users_list", {
    user: req.session.user,
    users: u.rows,
    currentUserRole,
  });
});

app.post(
  "/users/create",
  requireRole(["super_admin"]),
  async (req, res) => {
    try {
      const username = validateName(req.body.username, "Username");
      const passwordHash = await hashPassword(req.body.password);
      const role = await db.query(
        `SELECT id FROM roles WHERE name='user' LIMIT 1`
      );
      if (!role.rowCount) throw new Error("Role user chưa được khởi tạo");
      await db.query(
        `INSERT INTO users (username, password_hash, role_id) VALUES ($1, $2, $3)`,
        [username, passwordHash, role.rows[0].id]
      );
      await auditAdminAction({
        req,
        action: "user_create",
        targetType: "user",
        targetId: username,
        detail: { role: "user" },
      });
      res.redirect("/users");
    } catch (e) {
      res.send("Lỗi: username đã tồn tại");
    }
  }
);

app.get("/users/view/:id", requireRole(["super_admin"]), async (req, res) => {
  const userId = req.params.id;
  const u = await db.query(
    `SELECT u.id, u.username, u.is_active, u.created_at, r.name as role_name, u.role_id
     FROM users u LEFT JOIN roles r ON u.role_id = r.id WHERE u.id=$1`,
    [userId]
  );
  if (!u.rowCount) return res.redirect("/users");
  const recentDomains = await db.query(
    `SELECT d.id, d.domain_url, d.created_at, dua.access_level
     FROM domain_user_access dua
     JOIN domains d ON d.id=dua.domain_id
     WHERE dua.user_id=$1
     ORDER BY d.id DESC
     LIMIT 10`,
    [userId]
  );
  const recentCamps = await db.query(
    `SELECT id, name, created_at FROM campaigns WHERE user_id=$1 ORDER BY id DESC LIMIT 5`,
    [userId]
  );
  const roles = await db.query(
    `SELECT * FROM roles WHERE name IN ('super_admin', 'user') ORDER BY name`
  );
  res.render("admin/user_detail", {
    viewer: req.session.user,
    target: u.rows[0],
    recentDomains: recentDomains.rows,
    recentCamps: recentCamps.rows,
    roles: roles.rows,
  });
});

app.post(
  "/users/view/:id/role",
  requireRole(["super_admin"]),
  async (req, res) => {
    const role = await db.query(
      `SELECT id, name FROM roles
       WHERE id=$1 AND name IN ('super_admin', 'user') LIMIT 1`,
      [req.body.role_id]
    );
    if (!role.rowCount) return res.status(400).send("Role không hợp lệ");

    const target = await db.query(
      `SELECT r.name AS role_name
       FROM users u JOIN roles r ON r.id=u.role_id
       WHERE u.id=$1 LIMIT 1`,
      [req.params.id]
    );
    if (!target.rowCount) return res.status(404).send("Không tìm thấy user");
    if (
      target.rows[0].role_name === "super_admin" &&
      role.rows[0].name !== "super_admin"
    ) {
      const count = await db.query(
        `SELECT COUNT(*)::int AS total
         FROM users u JOIN roles r ON r.id=u.role_id
         WHERE r.name='super_admin' AND u.is_active=true`
      );
      if (count.rows[0].total <= 1) {
        return res.status(400).send("Phải giữ lại ít nhất một super admin");
      }
    }

    await db.query(`UPDATE users SET role_id=$1 WHERE id=$2`, [
      role.rows[0].id,
      req.params.id,
    ]);
    await auditAdminAction({
      req,
      action: "user_role_update",
      targetType: "user",
      targetId: req.params.id,
      detail: { role_id: role.rows[0].id, role_name: role.rows[0].name },
    });
    res.redirect("/users/view/" + req.params.id);
  }
);

const deleteUserHandler = async (req, res) => {
    // Các điều kiện bảo vệ khi xóa tài khoản.
    const targetId = req.params.id;
    const curUser = req.session.user;

    // Không cho phép tự xóa tài khoản đang đăng nhập.
    if (targetId == curUser.id) return res.send("Không thể tự xóa chính mình!");

    const target = await db.query(
      `SELECT r.name AS role_name
       FROM users u JOIN roles r ON r.id=u.role_id
       WHERE u.id=$1 LIMIT 1`,
      [targetId]
    );
    if (target.rows[0]?.role_name === "super_admin") {
      const count = await db.query(
        `SELECT COUNT(*)::int AS total
         FROM users u JOIN roles r ON r.id=u.role_id
         WHERE r.name='super_admin' AND u.is_active=true`
      );
      if (count.rows[0].total <= 1) {
        return res.status(400).send("Phải giữ lại ít nhất một super admin");
      }
    }

    const client = await db.connect();
    let transferredDomains = 0;
    try {
      await client.query("BEGIN");
      await client.query(
        `DELETE FROM domain_user_access WHERE user_id=$1`,
        [targetId]
      );
      const transferred = await client.query(
        `WITH moved AS (
           UPDATE domains
           SET user_id=$2, updated_by=$2, updated_at=now()
           WHERE user_id=$1
           RETURNING id
         )
         INSERT INTO domain_user_access
           (domain_id, user_id, access_level, granted_by)
         SELECT id, $2, 'owner', $2
         FROM moved
         ON CONFLICT (domain_id, user_id) DO UPDATE
           SET access_level='owner', granted_by=$2, updated_at=now()
         RETURNING domain_id`,
        [targetId, curUser.id]
      );
      transferredDomains = transferred.rowCount;
      await client.query(`UPDATE users SET is_active=false WHERE id=$1`, [
        targetId,
      ]);
      await client.query("COMMIT");
    } catch (error) {
      await client.query("ROLLBACK").catch(() => undefined);
      return res.status(500).send("Không thể vô hiệu hóa tài khoản");
    } finally {
      client.release();
    }
    await auditAdminAction({
      req,
      action: "user_deactivate",
      targetType: "user",
      targetId,
      detail: {
        transferred_domains: transferredDomains,
        new_owner_user_id: curUser.id,
      },
    });
    res.redirect("/users");
  };
app.get(
  "/users/delete/:id",
  requireRole(["super_admin"]),
  (req, res) => res.status(405).send("Use POST /users/delete/:id")
);
app.post(
  "/users/delete/:id",
  requireRole(["super_admin"]),
  deleteUserHandler
);

app.get("/admin/system", requireRole(["super_admin"]), async (req, res) => {
  const stats = await buildSystemStatus();
  res.render("admin/system", { user: req.session.user, ...stats });
});

app.get("/admin/system/data", requireRole(["super_admin"]), async (req, res) => {
  const stats = await buildSystemStatus();
  res.json(stats);
});

app.use(async (err, req, res, next) => {
  if (err && err.code === "EBADCSRFTOKEN") {
    await auditAdminAction({
      req,
      action: "csrf_rejected",
      targetType: "request",
      status: "failed",
      detail: { path: req.originalUrl, method: req.method },
    });
    return res.status(403).send("CSRF token khong hop le");
  }
  return next(err);
});

if (require.main === module) {
  const server = app.listen(PORT, process.env.BIND_HOST || "127.0.0.1", () => {
    console.log(`${product.name} admin listening on ${PORT}`);
    startSslProvisioner();
  });
  const shutdown = (signal) => {
    console.log(`${signal} received, closing admin service...`);
    stopSslProvisioner();
    server.close(async () => {
      await db.end().catch(() => undefined);
      process.exit(0);
    });
  };
  process.once("SIGTERM", () => shutdown("SIGTERM"));
  process.once("SIGINT", () => shutdown("SIGINT"));
}

module.exports = app;
