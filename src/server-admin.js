require("dotenv").config({ quiet: true });
const express = require("express");
const session = require("express-session");
const path = require("path");
const dns = require("dns");
const db = require("./config/db");

const app = express();
const PORT = 4002;

// Hàm sinh mã
const generateCode = (len = 8) => {
  const chars =
    "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
  let res = "";
  for (let i = 0; i < len; i++)
    res += chars.charAt(Math.floor(Math.random() * chars.length));
  return res;
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
  const rDom = await db.query(`SELECT * FROM domains ORDER BY id DESC`);
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
      `INSERT INTO domains (domain_url, safe_template, user_id) VALUES ($1, $2, $3)`,
      [req.body.domain_url, req.body.safe_template, req.session.user.id]
    );
    res.redirect("/");
  } catch (e) {
    res.send("Lỗi: Domain đã tồn tại");
  }
});

app.get("/domains/toggle/:id", checkAuth, async (req, res) => {
  await db.query(
    `UPDATE domains SET status = CASE WHEN status='active' THEN 'inactive' ELSE 'active' END WHERE id=$1`,
    [req.params.id]
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
    db.query(`UPDATE domains SET status='active' WHERE id=$1`, [req.params.id]);
    res.json({ status: "success", msg: "OK: " + addrs[0] });
  });
});

// --- LINK CAMPAIGNS ---
app.get("/domains/:id", checkAuth, async (req, res) => {
  const domainId = req.params.id;
  const rDom = await db.query(`SELECT * FROM domains WHERE id=$1`, [domainId]);
  if (!rDom.rowCount) return res.redirect("/");

  const rLinks = await db.query(
    `SELECT * FROM campaigns WHERE domain_id=$1 ORDER BY id DESC`,
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
  for (let l of links) {
    if (!l.is_active && l.filters?.countries?.length > 0) {
      const c = await db.query(
        `SELECT COUNT(*) FROM traffic_logs WHERE campaign_id=$1 AND action='safe_page' AND country = ANY($2)`,
        [l.id, l.filters.countries]
      );
      l.potential_traffic = c.rows[0].count;
    }
  }

  res.render("admin/domain_detail", {
    user: req.session.user,
    domain: rDom.rows[0],
    links,
  });
});

app.post("/campaigns/create", checkAuth, async (req, res) => {
  const { domain_id, name, target_url, rules_json, allowed_countries } =
    req.body;
  try {
    let filters = {};
    if (allowed_countries)
      filters.countries = Array.isArray(allowed_countries)
        ? allowed_countries
        : allowed_countries.split(",");

    const autoKey = "q";
    const autoValue = generateCode(8);

    await db.query(
      `
            INSERT INTO campaigns (domain_id, user_id, name, param_key, param_value, target_url, rules, filters)
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
        `,
      [
        domain_id,
        req.session.user.id,
        name,
        autoKey,
        autoValue,
        target_url,
        rules_json || "[]",
        filters,
      ]
    );

    res.redirect("/domains/" + domain_id);
  } catch (e) {
    res.send(e.message);
  }
});

app.get("/campaigns/toggle/:id", checkAuth, async (req, res) => {
  await db.query(`UPDATE campaigns SET is_active = NOT is_active WHERE id=$1`, [
    req.params.id,
  ]);
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
  const r = await db.query(`SELECT * FROM campaigns WHERE id=$1`, [
    req.params.id,
  ]);
  const d = await db.query(`SELECT * FROM domains WHERE id=$1`, [
    r.rows[0].domain_id,
  ]);
  res.render("admin/campaign_edit", {
    user: req.session.user,
    camp: r.rows[0],
    domain: d.rows[0],
  });
});

app.post("/campaigns/update/:id", checkAuth, async (req, res) => {
  const { name, target_url, rules_json, allowed_countries, domain_id } =
    req.body;
  let filters = {};
  if (allowed_countries)
    filters.countries = Array.isArray(allowed_countries)
      ? allowed_countries
      : allowed_countries.split(",");
  await db.query(
    `UPDATE campaigns SET name=$1, target_url=$2, rules=$3, filters=$4 WHERE id=$5`,
    [name, target_url, rules_json || "[]", filters, req.params.id]
  );
  res.redirect("/domains/" + domain_id);
});

// ...
app.get('/campaigns/:id/report', checkAuth, async (req, res) => {
    const campId = req.params.id;
    const rCamp = await db.query(`SELECT * FROM campaigns WHERE id=$1`, [campId]);
    
    // --- SỬA CÂU QUERY NÀY ---
    // Đếm FAIL bằng cách tìm action bắt đầu bằng 'safe_page%' (để bắt hết các lỗi sai params, sai country...)
    const stats = await db.query(`
        SELECT date(created_at) as day, 
               COUNT(*) FILTER (WHERE action = 'redirect') as redirects,
               COUNT(*) FILTER (WHERE action LIKE 'safe_page%') as safe
        FROM traffic_logs 
        WHERE campaign_id = $1 
        GROUP BY day 
        ORDER BY day DESC 
        LIMIT 7`, 
    [campId]);

    const logs = await db.query(`SELECT * FROM traffic_logs WHERE campaign_id=$1 ORDER BY id DESC LIMIT 100`, [campId]);
    res.render('admin/report', { camp: rCamp.rows[0], stats: stats.rows, logs: logs.rows });
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
