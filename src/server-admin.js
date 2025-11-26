require("dotenv").config({ quiet: true });
const express = require("express");
const session = require("express-session");
const path = require("path");
const dns = require("dns");
const db = require("./config/db");

const app = express();
const PORT = process.env.PORT || 4002;
const DEFAULT_TIMEZONE = "Asia/Ho_Chi_Minh";

// Hàm sinh mã
const generateCode = (len = 8) => {
  const chars =
    "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
  let res = "";
  for (let i = 0; i < len; i++)
    res += chars.charAt(Math.floor(Math.random() * chars.length));
  return res;
};

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

app.set("view engine", "ejs");
app.set("views", path.join(__dirname, "views"));
app.use(express.urlencoded({ extended: true }));
app.use(express.json());
app.use(express.static(path.join(__dirname, "../public")));

app.use(
  session({
    secret: "v2_secret_final_rbac",
    resave: false,
    saveUninitialized: true,
    cookie: { maxAge: 86400000 },
  })
);

// --- MIDDLEWARE RBAC (QUẢN LÝ QUYỀN) ---
const checkAuth = (req, res, next) => {
  if (!req.session.user) return res.redirect("/login");
  res.locals.currentUser = req.session.user;
  next();
};

// Middleware cho phép danh sách Role cụ thể truy cập
const requireRole = (rolesArray) => {
  return (req, res, next) => {
    if (!req.session.user) return res.redirect("/login");
    const userRole = req.session.user.role_name; // 'super_admin', 'admin', 'user'

    if (rolesArray.includes(userRole)) {
      next();
    } else {
      res.status(403).send(`⛔ Bạn không có quyền (Role: ${userRole})`);
    }
  };
};

// AUTH
app.get("/login", (req, res) => res.render("admin/login", { error: null }));
app.post("/login", async (req, res) => {
  const { username, password } = req.body;
  const r = await db.query(
    `
        SELECT u.*, r.name as role_name FROM users u 
        JOIN roles r ON u.role_id = r.id WHERE u.username = $1
    `,
    [username]
  );

  if (r.rowCount > 0 && password === r.rows[0].password_hash) {
    req.session.user = r.rows[0];
    return res.redirect("/");
  }
  res.render("admin/login", { error: "Sai thông tin" });
});
app.get("/logout", (req, res) => {
  req.session.destroy();
  res.redirect("/login");
});

// --- DASHBOARD ---
app.get("/", checkAuth, async (req, res) => {
  const rDom = await db.query(
    `
      SELECT d.*, cu.username AS created_by_name, uu.username AS updated_by_name,
             (SELECT COUNT(*) FROM campaigns c WHERE c.domain_id = d.id) AS link_count,
             (SELECT COUNT(*) FROM campaigns c WHERE c.domain_id = d.id AND c.is_active) AS link_active
      FROM domains d
      LEFT JOIN users cu ON d.user_id = cu.id
      LEFT JOIN users uu ON d.updated_by = uu.id
      ORDER BY d.id DESC
    `
  );
  const stats = await db.query(`
        SELECT (SELECT COUNT(*) FROM domains) as total_domains,
               (SELECT COUNT(*) FROM campaigns) as total_links,
               (SELECT COUNT(*) FROM traffic_logs) as total_traffic
    `);
  res.render("admin/dashboard", {
    user: req.session.user,
    domains: rDom.rows,
    stats: stats.rows[0],
  });
});

// --- DOMAIN (CRUD) ---
app.post("/domains/create", checkAuth, async (req, res) => {
  try {
    await db.query(
      `INSERT INTO domains (domain_url, safe_template, user_id, updated_by) VALUES ($1, $2, $3, $4)`,
      [
        req.body.domain_url,
        req.body.safe_template,
        req.session.user.id,
        req.session.user.id,
      ]
    );
    res.redirect("/");
  } catch (e) {
    res.send("Lỗi: Domain đã tồn tại");
  }
});

app.get("/domains/toggle/:id", checkAuth, async (req, res) => {
  await db.query(
    `UPDATE domains SET status = CASE WHEN status='active' THEN 'inactive' ELSE 'active' END, updated_by=$2 WHERE id=$1`,
    [req.params.id, req.session.user.id]
  );
  res.redirect("/");
});

// CHỈ SUPER ADMIN ĐƯỢC XÓA DOMAIN
app.get(
  "/domains/delete/:id",
  requireRole(["super_admin"]),
  async (req, res) => {
    try {
      // Xóa cascade trong DB sẽ tự xóa link, nhưng cần xóa log thủ công nếu chưa set cascade cho log
      // Ở đây giả sử DB set cascade rồi.
      await db.query(`DELETE FROM domains WHERE id=$1`, [req.params.id]);
      res.redirect("/");
    } catch (e) {
      res.send("Lỗi khi xóa domain: " + e.message);
    }
  }
);

app.get("/domains/:id/verify", checkAuth, async (req, res) => {
  const r = await db.query(`SELECT domain_url FROM domains WHERE id=$1`, [
    req.params.id,
  ]);
  if (!r.rowCount) return res.json({ status: "error" });
  dns.resolve4(r.rows[0].domain_url, (err, addrs) => {
    if (err) return res.json({ status: "error", msg: "Chưa trỏ DNS" });
    db.query(`UPDATE domains SET status='active', updated_by=$2 WHERE id=$1`, [
      req.params.id,
      req.session.user.id,
    ]);
    res.json({ status: "success", msg: "OK: " + addrs[0] });
  });
});

// --- LINK CAMPAIGNS ---
app.get("/domains/:id", checkAuth, async (req, res) => {
  const domainId = req.params.id;
  const rDom = await db.query(
    `
      SELECT d.*, cu.username AS created_by_name, uu.username AS updated_by_name
      FROM domains d
      LEFT JOIN users cu ON d.user_id = cu.id
      LEFT JOIN users uu ON d.updated_by = uu.id
      WHERE d.id=$1
    `,
    [domainId]
  );
  if (!rDom.rowCount) return res.redirect("/");

  const rLinks = await db.query(
    `
      SELECT c.*, cu.username AS created_by_name, uu.username AS updated_by_name
      FROM campaigns c
      LEFT JOIN users cu ON c.user_id = cu.id
      LEFT JOIN users uu ON c.updated_by = uu.id
      WHERE c.domain_id=$1
      ORDER BY c.id DESC
    `,
    [domainId]
  );

  const linkStats = await db.query(
    `
      SELECT COUNT(*) AS total,
             COUNT(*) FILTER (WHERE is_active) AS active,
             COUNT(*) FILTER (WHERE NOT is_active) AS inactive
      FROM campaigns WHERE domain_id=$1
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

  // Smart Alert Logic (Đếm truy cập sạch từ quốc gia allow)
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
    linkStats: linkStats.rows[0],
  });
});

app.post("/campaigns/create", checkAuth, async (req, res) => {
  const {
    domain_id,
    name,
    target_url,
    rules_json,
    allowed_countries,
    copy_from_id,
  } = req.body;
  try {
    let rulesPayload = [];
    try {
      rulesPayload = rules_json ? JSON.parse(rules_json) : [];
    } catch (e) {
      return res.send("Rules khong hop le");
    }
    let rulesPayloadJson = JSON.stringify(rulesPayload || []);
    const dup = await db.query(
      `SELECT 1 FROM campaigns WHERE domain_id=$1 AND LOWER(name)=LOWER($2) LIMIT 1`,
      [domain_id, name]
    );
    if (dup.rowCount) return res.send("Ten link bi trung trong domain");

    let filters = {};
    if (allowed_countries)
      filters.countries = Array.isArray(allowed_countries)
        ? allowed_countries
        : allowed_countries.split(",");

    if (copy_from_id && rulesPayload.length === 0 && !allowed_countries) {
      const rCfg = await db.query(
        `SELECT rules, filters FROM campaigns WHERE id=$1 AND domain_id=$2`,
        [copy_from_id, domain_id]
      );
      if (rCfg.rowCount) {
        rulesPayload = rCfg.rows[0].rules || [];
        filters = rCfg.rows[0].filters || {};
        rulesPayloadJson = JSON.stringify(rulesPayload || []);
      }
    }
    const filtersJson = JSON.stringify(filters || {});

    const autoKey = "q";
    const autoValue = generateCode(8);

    await db.query(
      `
            INSERT INTO campaigns (domain_id, user_id, name, param_key, param_value, target_url, rules, filters, updated_by)
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
        `,
      [
        domain_id,
        req.session.user.id,
        name,
        autoKey,
        autoValue,
        target_url,
        rulesPayloadJson,
        filtersJson,
        req.session.user.id,
      ]
    );

    res.redirect("/domains/" + domain_id);
  } catch (e) {
    res.send(e.message);
  }
});

app.get("/campaigns/toggle/:id", checkAuth, async (req, res) => {
  await db.query(
    `UPDATE campaigns SET is_active = NOT is_active, updated_by=$2 WHERE id=$1`,
    [req.params.id, req.session.user.id]
  );
  const r = await db.query(`SELECT domain_id FROM campaigns WHERE id=$1`, [
    req.params.id,
  ]);
  res.redirect("/domains/" + r.rows[0].domain_id);
});

// CHỈ SUPER ADMIN ĐƯỢC XÓA LINK
app.get(
  "/campaigns/delete/:id",
  requireRole(["super_admin"]),
  async (req, res) => {
    const r = await db.query(`SELECT domain_id FROM campaigns WHERE id=$1`, [
      req.params.id,
    ]);
    if (r.rowCount) {
      await db.query(`DELETE FROM traffic_logs WHERE campaign_id=$1`, [
        req.params.id,
      ]);
      await db.query(`DELETE FROM campaigns WHERE id=$1`, [req.params.id]);
      res.redirect("/domains/" + r.rows[0].domain_id);
    } else {
      res.redirect("/");
    }
  }
);

app.get("/campaigns/edit/:id", checkAuth, async (req, res) => {
  const r = await db.query(
    `SELECT c.*, cu.username AS created_by_name, uu.username AS updated_by_name 
     FROM campaigns c
     LEFT JOIN users cu ON c.user_id = cu.id
     LEFT JOIN users uu ON c.updated_by = uu.id
     WHERE c.id=$1`,
    [req.params.id]
  );
  if (!r.rowCount) return res.redirect("/");
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

app.post("/campaigns/update/:id", checkAuth, async (req, res) => {
  const { name, target_url, rules_json, allowed_countries, domain_id } =
    req.body;
  let filters = {};
  let rulesPayload = [];
  try {
    rulesPayload = rules_json ? JSON.parse(rules_json) : [];
  } catch (e) {
    return res.send("Rules khong hop le");
  }
  const rulesPayloadJson = JSON.stringify(rulesPayload || []);
  if (allowed_countries)
    filters.countries = Array.isArray(allowed_countries)
      ? allowed_countries
      : allowed_countries.split(",");
  const dup = await db.query(
    `SELECT 1 FROM campaigns WHERE domain_id=$1 AND LOWER(name)=LOWER($2) AND id<>$3 LIMIT 1`,
    [domain_id, name, req.params.id]
  );
  if (dup.rowCount) return res.send("Ten link bi trung trong domain");

  const filtersJson = JSON.stringify(filters || {});
  await db.query(
    `UPDATE campaigns SET name=$1, target_url=$2, rules=$3, filters=$4, updated_by=$5 WHERE id=$6`,
    [
      name,
      target_url,
      rulesPayloadJson,
      filtersJson,
      req.session.user.id,
      req.params.id,
    ]
  );
  res.redirect("/domains/" + domain_id);
});

app.get("/api/campaigns/:id/config", checkAuth, async (req, res) => {
  const campId = req.params.id;
  const r = await db.query(
    `SELECT id, name, rules, filters, param_key, param_value FROM campaigns WHERE id=$1`,
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

// ...
app.get("/campaigns/:id/report", checkAuth, async (req, res) => {
  const campId = req.params.id;
  const range = req.query.range || "today"; // today / 7d / week / month / custom
  const now = new Date();
  let start = new Date(now);
  let end = new Date(now);
  let grouping = "day";

  const parseDate = (s) => {
    const d = new Date(s);
    return isNaN(d) ? null : d;
  };

  if (range === "7d") {
    start.setDate(start.getDate() - 7);
    grouping = "day";
  } else if (range === "week") {
    const day = start.getDay();
    const diff = day === 0 ? -6 : 1 - day; // Monday as start
    start.setDate(start.getDate() + diff);
    end = new Date(start);
    end.setDate(start.getDate() + 7);
    grouping = "day";
  } else if (range === "month") {
    start = new Date(now.getFullYear(), now.getMonth(), 1);
    end = new Date(now.getFullYear(), now.getMonth() + 1, 1);
    grouping = "day";
  } else if (range === "custom" && req.query.start_date && req.query.end_date) {
    const s = parseDate(req.query.start_date);
    const e = parseDate(req.query.end_date);
    if (s && e && e > s) {
      start = s;
      end = e;
      grouping = "day";
    }
  } else {
    // today
    start = new Date(now.getFullYear(), now.getMonth(), now.getDate());
    end = new Date(start);
    end.setDate(start.getDate() + 1);
    grouping = "hour";
  }

  if (!end || end <= start) {
    end = new Date(start);
    end.setDate(start.getDate() + 1);
  }

  const prevStart = new Date(start);
  const prevEnd = new Date(end);
  const diffMs = end.getTime() - start.getTime();
  prevStart.setTime(start.getTime() - diffMs);
  prevEnd.setTime(end.getTime() - diffMs);

  const rCamp = await db.query(`SELECT * FROM campaigns WHERE id=$1`, [
    campId,
  ]);
  if (!rCamp.rowCount) return res.redirect("/");

  const stats = await db.query(
    `
        SELECT date_trunc($4::text, created_at) as day, 
               COUNT(*) FILTER (WHERE action = 'redirect') as redirects,
               COUNT(*) FILTER (WHERE action LIKE 'safe_page%') as safe
        FROM traffic_logs 
        WHERE campaign_id = $1 
          AND created_at >= $2
          AND created_at < $3
        GROUP BY day 
        ORDER BY day ASC
      `,
    [campId, start, end, grouping]
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
               COUNT(*) as hits,
               COUNT(*) FILTER (WHERE action='redirect') as redirects
        FROM traffic_logs
        WHERE campaign_id=$1 
          AND created_at >= $2
          AND created_at < $3
        GROUP BY country
        ORDER BY hits DESC
        LIMIT 6
      `,
    [campId, start, end]
  );

  const logs = await db.query(
    `SELECT * FROM traffic_logs WHERE campaign_id=$1 AND created_at >= $2 AND created_at < $3 ORDER BY id DESC LIMIT 50`,
    [campId, start, end]
  );

  const summary = {
    redirects: Number(totals.rows[0]?.redirects || 0),
    safe: Number(totals.rows[0]?.safe || 0),
  };
  summary.total = summary.redirects + summary.safe;

  const previous = {
    redirects: Number(prevTotals.rows[0]?.redirects || 0),
    safe: Number(prevTotals.rows[0]?.safe || 0),
  };
  previous.total = previous.redirects + previous.safe;

  summary.pass_rate = summary.total
    ? Math.round((summary.redirects / summary.total) * 1000) / 10
    : 0;
  summary.delta_redirects = summary.redirects - previous.redirects;
  summary.redirect_growth =
    previous.redirects > 0
      ? Math.round((summary.delta_redirects / previous.redirects) * 1000) / 10
      : null;

  const labelEnd = new Date(end);
  if (range !== "today") labelEnd.setDate(labelEnd.getDate() - 1);
  const rangeLabel = `${start.toLocaleDateString("vi-VN")} - ${labelEnd.toLocaleDateString("vi-VN")}`;

  res.render("admin/report", {
    camp: rCamp.rows[0],
    stats: stats.rows,
    logs: logs.rows,
    summary,
    countryStats: countryStats.rows,
    previous,
    range,
    start,
    end,
    rangeLabel,
  });
});

app.get("/campaigns/:id/logs", checkAuth, async (req, res) => {
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
  if (!rCamp.rowCount) return res.redirect("/");
  let sql = `SELECT * FROM traffic_logs WHERE campaign_id=$1 AND created_at >= $2 AND created_at < $3`;
  const params = [campId, start, end];
  if (action) {
    params.push(action);
    sql += ` AND action=$${params.length}`;
  }
  sql += ` ORDER BY id DESC LIMIT ${limit}`;
  const logs = await db.query(sql, params);
  res.render("admin/logs", {
    camp: rCamp.rows[0],
    logs: logs.rows,
    action,
    limit,
    start,
    end,
  });
});

app.get("/campaigns/:id/report/export", checkAuth, async (req, res) => {
  const campId = req.params.id;
  const { normalized, start, end } = parseMonthRange(req.query.month);
  const rCamp = await db.query(`SELECT name FROM campaigns WHERE id=$1`, [
    campId,
  ]);
  if (!rCamp.rowCount) return res.redirect("/");

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

// --- MODULE QUẢN TRỊ USER (PHÂN QUYỀN) ---
// Chỉ Super Admin và Admin mới được vào xem danh sách
app.get("/users", requireRole(["super_admin", "admin"]), async (req, res) => {
  const currentUserRole = req.session.user.role_name;
  let sql = "";

  if (currentUserRole === "super_admin") {
    // Super Admin thấy tất cả
    sql = `SELECT u.id, u.username, u.is_active, u.created_at, r.name as role_name 
               FROM users u LEFT JOIN roles r ON u.role_id = r.id ORDER BY u.id ASC`;
  } else {
    // Admin chỉ thấy User thường
    sql = `SELECT u.id, u.username, u.is_active, u.created_at, r.name as role_name 
               FROM users u LEFT JOIN roles r ON u.role_id = r.id 
               WHERE r.name = 'user' ORDER BY u.id ASC`;
  }

  const u = await db.query(sql);

  // Lấy list Role để tạo user mới
  let roleSql = "SELECT * FROM roles";
  if (currentUserRole === "admin") roleSql += " WHERE name = 'user'"; // Admin chỉ tạo đc User
  const roles = await db.query(roleSql);

  res.render("admin/users_list", {
    user: req.session.user,
    users: u.rows,
    roles: roles.rows,
    currentUserRole,
  });
});

app.post(
  "/users/create",
  requireRole(["super_admin", "admin"]),
  async (req, res) => {
    // Validate: Admin không được tạo Super Admin hay Admin khác (Chặn ở backend cho chắc)
    if (req.session.user.role_name === "admin") {
      const rRole = await db.query(`SELECT name FROM roles WHERE id=$1`, [
        req.body.role_id,
      ]);
      if (rRole.rows[0].name !== "user")
        return res.send("Admin chỉ được tạo User thường!");
    }

    try {
      await db.query(
        `INSERT INTO users (username, password_hash, role_id) VALUES ($1, $2, $3)`,
        [req.body.username, req.body.password, req.body.role_id]
      );
      res.redirect("/users");
    } catch (e) {
      res.send("Lỗi: Username đã tồn tại");
    }
  }
);

app.get("/users/view/:id", requireRole(["super_admin", "admin"]), async (req, res) => {
  const userId = req.params.id;
  const u = await db.query(
    `SELECT u.id, u.username, u.is_active, u.created_at, r.name as role_name, u.role_id 
     FROM users u LEFT JOIN roles r ON u.role_id = r.id WHERE u.id=$1`,
    [userId]
  );
  if (!u.rowCount) return res.redirect("/users");
  const recentDomains = await db.query(
    `SELECT id, domain_url, created_at FROM domains WHERE user_id=$1 ORDER BY id DESC LIMIT 5`,
    [userId]
  );
  const recentCamps = await db.query(
    `SELECT id, name, created_at FROM campaigns WHERE user_id=$1 ORDER BY id DESC LIMIT 5`,
    [userId]
  );
  const roles = await db.query(`SELECT * FROM roles`);
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
    await db.query(`UPDATE users SET role_id=$1 WHERE id=$2`, [
      req.body.role_id,
      req.params.id,
    ]);
    res.redirect("/users/view/" + req.params.id);
  }
);

app.get(
  "/users/delete/:id",
  requireRole(["super_admin", "admin"]),
  async (req, res) => {
    // Logic chặn xóa
    const targetId = req.params.id;
    const curUser = req.session.user;

    // 1. Không tự xóa mình
    if (targetId == curUser.id) return res.send("Không thể tự xóa chính mình!");

    // 2. Admin không được xóa Super Admin hoặc Admin khác
    if (curUser.role_name === "admin") {
      const rTarget = await db.query(
        `SELECT r.name FROM users u JOIN roles r ON u.role_id=r.id WHERE u.id=$1`,
        [targetId]
      );
      if (rTarget.rows[0].name !== "user")
        return res.send("Bạn chỉ được xóa User thường!");
    }

    await db.query(`DELETE FROM users WHERE id=$1`, [targetId]);
    res.redirect("/users");
  }
);

app.listen(PORT, () => console.log(`Admin V2 running on ${PORT}`));
