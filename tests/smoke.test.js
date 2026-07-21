process.env.CACHE_ENABLED = "false";
process.env.TRAFFIC_BUFFER_ENABLED = "false";
process.env.COUNTER_BUFFER_ENABLED = "false";

const test = require("node:test");
const assert = require("node:assert/strict");
const request = require("supertest");
const ejs = require("ejs");
const fs = require("fs");
const path = require("path");

const db = require("../src/config/db");
const adsApp = require("../src/server-ads");
const adminApp = require("../src/server-admin");
const {
  SAFE_TEMPLATES,
  normalizeSafeTemplate,
} = require("../src/utils/validation");

const product = {
  name: "LinkPilot",
  shortName: "LP",
  tagline: "Redirect & Campaign Control",
  support: "",
};

const extractCsrf = (html) => {
  const match = html.match(/name="_csrf"\s+value="([^"]+)"/);
  assert.ok(match, "missing csrf token");
  return match[1];
};

test("product exposes exactly the two fixed safe page templates", () => {
  assert.deepEqual([...SAFE_TEMPLATES], ["clean", "age_gate"]);
  assert.equal(normalizeSafeTemplate("age_gate"), "age_gate");
  assert.equal(normalizeSafeTemplate("custom"), "clean");
});

test("product login, welcome and dashboard views render", async () => {
  const views = path.join(__dirname, "../src/views/admin");
  const user = { username: "admin", role_name: "super_admin" };
  const login = await ejs.renderFile(path.join(views, "login.ejs"), {
    product,
    csrfToken: "test-token",
    error: null,
  });
  const welcome = await ejs.renderFile(path.join(views, "welcome.ejs"), {
    product,
    csrfToken: "test-token",
    user,
  });
  const dashboard = await ejs.renderFile(path.join(views, "dashboard.ejs"), {
    product,
    csrfToken: "test-token",
    user,
    stats: { total_domains: 0, total_links: 0, total_traffic: 0 },
    domains: [],
  });
  const shortLinks = await ejs.renderFile(path.join(views, "short_links.ejs"), {
    product,
    csrfToken: "test-token",
    user,
    domains: [{ id: 1, domain_url: "example.com", status: "active" }],
    links: [],
  });
  const waitPage = await ejs.renderFile(
    path.join(__dirname, "../src/views/safepages/redirect_wait.ejs"),
    {
      product,
      targetUrl: "https://target.test/landing?utm_source=email",
      delaySeconds: 3,
    }
  );
  assert.match(login, /Chào mừng trở lại/);
  assert.match(welcome, /Hai luồng redirect/);
  assert.match(dashboard, /Chưa có domain nào/);
  assert.match(shortLinks, /name="redirect_delay_seconds"/);
  assert.match(shortLinks, /min="1" max="30"/);
  assert.doesNotMatch(shortLinks, /name="redirect_mode"/);
  assert.match(waitPage, /data-delay="3"/);
  assert.match(waitPage, /https:\/\/target\.test\/landing\?utm_source=email/);
});

test("Facebook setup template no longer copies fbclid or fbcid", () => {
  const source = fs.readFileSync(
    path.join(__dirname, "../src/views/admin/domain_detail.ejs"),
    "utf8"
  );
  assert.doesNotMatch(source, /fbclid|fbcid/i);
  assert.match(source, /addNewRule\('campaign_id', 'exists'\)/);
});

test("contextual help is available across the admin product", () => {
  const viewsRoot = path.join(__dirname, "../src/views");
  const adminRoot = path.join(viewsRoot, "admin");
  const criticalViews = [
    "dashboard.ejs",
    "domain_detail.ejs",
    "campaign_edit.ejs",
    "short_links.ejs",
    "report_v2.ejs",
    "short_link_report.ejs",
    "system.ejs",
    "users_list.ejs",
  ];

  let helpAnchorCount = 0;
  criticalViews.forEach((file) => {
    const source = fs.readFileSync(path.join(adminRoot, file), "utf8");
    const count = (source.match(/data-help=/g) || []).length;
    assert.ok(count > 0, `${file} must contain contextual help`);
    helpAnchorCount += count;
  });

  const footer = fs.readFileSync(
    path.join(viewsRoot, "partials/footer.ejs"),
    "utf8"
  );
  const css = fs.readFileSync(
    path.join(__dirname, "../public/css/app.css"),
    "utf8"
  );
  const users = fs.readFileSync(path.join(adminRoot, "users_list.ejs"), "utf8");

  assert.ok(helpAnchorCount >= 30, "major admin sections should be documented");
  assert.match(footer, /id="globalHelpPopover"/);
  assert.match(footer, /aria-expanded/);
  assert.match(footer, /mouseenter/);
  assert.match(footer, /keydown/);
  assert.match(css, /\.help-tip/);
  assert.match(css, /\.help-popover/);
  assert.match(users, /type="password"/);
  assert.match(users, /autocomplete="new-password"/);
});

test("all EJS view templates compile", () => {
  const viewsRoot = path.join(__dirname, "../src/views");
  const folders = ["admin", "partials", "safepages"];

  folders.forEach((folder) => {
    const folderPath = path.join(viewsRoot, folder);
    fs.readdirSync(folderPath)
      .filter((file) => file.endsWith(".ejs"))
      .forEach((file) => {
        const fullPath = path.join(folderPath, file);
        const source = fs.readFileSync(fullPath, "utf8");
        assert.doesNotThrow(
          () => ejs.compile(source, { filename: fullPath }),
          `${folder}/${file} should compile`
        );
      });
  });
});

test("health endpoints report database readiness", async () => {
  db.query = async (sql) => {
    assert.equal(sql, "SELECT 1");
    return { rowCount: 1, rows: [{ '?column?': 1 }] };
  };
  const [adsHealth, adminHealth] = await Promise.all([
    request(adsApp).get("/healthz"),
    request(adminApp).get("/healthz"),
  ]);
  assert.equal(adsHealth.status, 200);
  assert.equal(adminHealth.status, 200);
  assert.equal(adsHealth.body.product, "LinkPilot");
  assert.equal(adminHealth.body.product, "LinkPilot");
});

test("ads redirects matched campaign and appends missing params", async () => {
  db.query = async (sql, params) => {
    if (sql.includes("FROM domains WHERE domain_url")) {
      return {
        rowCount: 1,
        rows: [
          {
            id: 1,
            domain_url: "example.com",
            status: "active",
            safe_template: "news",
            safe_content: { title: "News", headline: "Latest" },
          },
        ],
      };
    }
    if (sql.includes("FROM campaigns c")) {
      return {
        rowCount: 1,
        rows: [
          {
            id: 7,
            domain_id: 1,
            is_active: true,
            filters: {},
            rules: [],
            target_url: "https://target.test/landing?fixed=1",
          },
        ],
      };
    }
    if (
      sql.includes("UPDATE campaigns SET stats_redirects") ||
      sql.includes("INSERT INTO traffic_logs")
    ) {
      return { rowCount: 1, rows: [] };
    }
    throw new Error(`Unhandled query in ads redirect test: ${sql}`);
  };

  const res = await request(adsApp)
    .get("/?q=abc123&utm_source=facebook")
    .set("Host", "example.com")
    .set("User-Agent", "Mozilla/5.0");

  assert.equal(res.status, 302);
  assert.match(res.headers.location, /^https:\/\/target\.test\/landing\?/);
  assert.match(res.headers.location, /fixed=1/);
  assert.match(res.headers.location, /q=abc123/);
  assert.match(res.headers.location, /utm_source=facebook/);
  assert.ok(res.headers["x-request-id"]);
});

test("ads gives legacy short links the default 3-second wait", async () => {
  let clickUpdated = false;
  let trafficLogged = false;

  db.query = async (sql, params) => {
    if (sql.includes("FROM domains WHERE domain_url")) {
      return {
        rowCount: 1,
        rows: [
          {
            id: 3,
            domain_url: "example.com",
            status: "active",
            safe_template: "news",
            safe_content: { title: "News", headline: "Latest" },
          },
        ],
      };
    }
    if (sql.includes("FROM short_links")) {
      assert.deepEqual(params, [3, "spring2026"]);
      return {
        rowCount: 1,
        rows: [
          {
            id: 12,
            domain_id: 3,
            code: "spring2026",
            is_active: true,
            target_url: "https://target.test/promo",
          },
        ],
      };
    }
    if (sql.includes("UPDATE short_links SET clicks")) {
      clickUpdated = true;
      assert.deepEqual(params, [12]);
      return { rowCount: 1, rows: [] };
    }
    if (sql.includes("INSERT INTO traffic_logs")) {
      trafficLogged = true;
      assert.equal(params[8], "short_redirect");
      assert.equal(params[12], 12);
      return { rowCount: 1, rows: [] };
    }
    throw new Error(`Unhandled query in short link test: ${sql}`);
  };

  const res = await request(adsApp)
    .get("/s/Spring2026?utm_source=email")
    .set("Host", "example.com")
    .set("User-Agent", "Mozilla/5.0");

  assert.equal(res.status, 200);
  assert.match(res.text, /data-delay="3"/);
  assert.match(res.text, /https:\/\/target\.test\/promo\?utm_source=email/);
  assert.equal(clickUpdated, true);
  assert.equal(trafficLogged, true);
  assert.ok(res.headers["x-request-id"]);
});

test("ads renders a 3-second wait page without checking campaign rules", async () => {
  let campaignWasChecked = false;

  db.query = async (sql, params) => {
    if (sql.includes("FROM domains WHERE domain_url")) {
      return {
        rowCount: 1,
        rows: [{ id: 4, domain_url: "wait.example", status: "active" }],
      };
    }
    if (sql.includes("FROM short_links")) {
      assert.deepEqual(params, [4, "wait3"]);
      return {
        rowCount: 1,
        rows: [
          {
            id: 19,
            domain_id: 4,
            code: "wait3",
            is_active: true,
            redirect_delay_seconds: 3,
            target_url: "https://target.test/delayed?fixed=1",
          },
        ],
      };
    }
    if (sql.includes("FROM campaigns c")) {
      campaignWasChecked = true;
      throw new Error("Delayed short links must bypass campaigns");
    }
    if (
      sql.includes("UPDATE short_links SET clicks") ||
      sql.includes("INSERT INTO traffic_logs")
    ) {
      return { rowCount: 1, rows: [] };
    }
    throw new Error(`Unhandled query in delayed short link test: ${sql}`);
  };

  const res = await request(adsApp)
    .get("/s/wait3?utm_source=email&campaign_id=sale")
    .set("Host", "wait.example")
    .set("User-Agent", "Mozilla/5.0");

  assert.equal(res.status, 200);
  assert.equal(campaignWasChecked, false);
  assert.match(res.headers["cache-control"], /no-store/);
  assert.match(res.text, /data-delay="3"/);
  assert.match(res.text, /utm_source=email/);
  assert.match(res.text, /campaign_id=sale/);
  assert.match(res.text, /Tiếp tục ngay/);
});

test("ads renders safe page when no active campaign matches", async () => {
  db.query = async (sql) => {
    if (sql.includes("FROM domains WHERE domain_url")) {
      return {
        rowCount: 1,
        rows: [
          {
            id: 1,
            domain_url: "example.com",
            status: "active",
            safe_template: "shop",
            safe_content: { title: "Shop Title", headline: "Shop Headline" },
          },
        ],
      };
    }
    if (sql.includes("INSERT INTO traffic_logs")) {
      return { rowCount: 1, rows: [] };
    }
    if (sql.includes("FROM campaigns c")) {
      return { rowCount: 0, rows: [] };
    }
    throw new Error(`Unhandled query in ads safe test: ${sql}`);
  };

  const res = await request(adsApp)
    .get("/?q=missing")
    .set("Host", "example.com")
    .set("User-Agent", "Mozilla/5.0");

  assert.equal(res.status, 200);
  assert.match(res.text, /Shop Headline/);
  assert.ok(res.headers["x-request-id"]);
});

test("ads renders clean safe page template", async () => {
  db.query = async (sql) => {
    if (sql.includes("FROM domains WHERE domain_url")) {
      return {
        rowCount: 1,
        rows: [
          {
            id: 2,
            domain_url: "clean.example",
            status: "active",
            safe_template: "clean",
            safe_content: { title: "Clean Site", headline: "Clean Headline" },
          },
        ],
      };
    }
    if (sql.includes("INSERT INTO traffic_logs")) {
      return { rowCount: 1, rows: [] };
    }
    if (sql.includes("FROM campaigns c")) {
      return { rowCount: 0, rows: [] };
    }
    throw new Error(`Unhandled query in ads clean safe test: ${sql}`);
  };

  const res = await request(adsApp)
    .get("/?q=missing")
    .set("Host", "clean.example")
    .set("User-Agent", "Mozilla/5.0");

  assert.equal(res.status, 200);
  assert.match(res.text, /Clean Headline/);
  assert.match(res.text, /clean\.example/);
});

test("legacy custom safe page values fall back to the fixed clean template", async () => {
  db.query = async (sql) => {
    if (sql.includes("FROM domains WHERE domain_url")) {
      return {
        rowCount: 1,
        rows: [
          {
            id: 4,
            domain_url: "custom.example",
            status: "active",
            safe_template: "custom",
            safe_content: {
              title: "Custom Site",
              headline: "Custom Headline",
              custom_html:
                '<section class="hero" onclick="alert(1)"><h1>Custom Safe</h1><script>alert(1)</script><a href="javascript:alert(1)">Bad</a></section>',
              custom_css: ".hero { color: red; }</style><script>alert(1)</script>",
            },
          },
        ],
      };
    }
    if (sql.includes("INSERT INTO traffic_logs")) {
      return { rowCount: 1, rows: [] };
    }
    if (sql.includes("FROM campaigns c")) {
      return { rowCount: 0, rows: [] };
    }
    throw new Error(`Unhandled query in ads custom safe test: ${sql}`);
  };

  const res = await request(adsApp)
    .get("/?q=missing")
    .set("Host", "custom.example")
    .set("User-Agent", "Mozilla/5.0");

  assert.equal(res.status, 200);
  assert.match(res.text, /Custom Headline/);
  assert.doesNotMatch(res.text, /Custom Safe/);
  assert.doesNotMatch(res.text, /<script/i);
  assert.doesNotMatch(res.text, /onclick=/i);
  assert.doesNotMatch(res.text, /javascript:/i);
});

test("ads uses the fixed mobile age-gate campaign override", async () => {
  db.query = async (sql) => {
    if (sql.includes("FROM domains WHERE domain_url")) {
      return {
        rowCount: 1,
        rows: [
          {
            id: 5,
            domain_url: "override.example",
            status: "active",
            safe_template: "clean",
            safe_content: { title: "Domain Default", headline: "Domain Safe" },
          },
        ],
      };
    }
    if (sql.includes("FROM campaigns c")) {
      return {
        rowCount: 1,
        rows: [
          {
            id: 21,
            domain_id: 5,
            is_active: false,
            filters: {},
            rules: [],
            target_url: "https://target.test/landing",
            safe_page_template: "age_gate",
            safe_page_content: null,
          },
        ],
      };
    }
    if (sql.includes("INSERT INTO traffic_logs")) {
      return { rowCount: 1, rows: [] };
    }
    throw new Error(`Unhandled query in campaign safe override test: ${sql}`);
  };

  const res = await request(adsApp)
    .get("/?q=abc123")
    .set("Host", "override.example")
    .set("User-Agent", "Mozilla/5.0");

  assert.equal(res.status, 200);
  assert.match(res.text, /safe-age-gate\.jpeg/);
  assert.match(res.text, /data-choice="yes"/);
  assert.doesNotMatch(res.text, /Domain Safe/);
});

test("redirect engine serves the bundled age-gate image", async () => {
  const res = await request(adsApp).get("/assets/images/safe-age-gate.jpeg");
  assert.equal(res.status, 200);
  assert.match(res.headers["content-type"], /^image\/jpeg/);
  assert.ok(Number(res.headers["content-length"] || res.body.length) > 40000);
});

test("admin login lazy-migrates plain password and creates domain via csrf form", async () => {
  let migratedHash = null;
  let insertedDomain = null;

  db.query = async (sql, params) => {
    if (sql.includes("SELECT u.*, r.name as role_name FROM users")) {
      return {
        rowCount: 1,
        rows: [
          {
            id: 10,
            username: "admin",
            password_hash: "secret123",
            role_id: 1,
            role_name: "super_admin",
          },
        ],
      };
    }
    if (sql.includes("UPDATE users SET password_hash=$1")) {
      migratedHash = params[0];
      return { rowCount: 1, rows: [] };
    }
    if (sql.includes("FROM domains d")) {
      return { rowCount: 0, rows: [] };
    }
    if (sql.includes("SELECT (SELECT COUNT(*) FROM domains)")) {
      return {
        rowCount: 1,
        rows: [{ total_domains: 0, total_links: 0, total_traffic: 0 }],
      };
    }
    if (sql.includes("INSERT INTO domains (domain_url, safe_template")) {
      insertedDomain = params;
      return { rowCount: 1, rows: [] };
    }
    if (sql.includes("INSERT INTO admin_audit_logs")) {
      return { rowCount: 1, rows: [] };
    }
    throw new Error(`Unhandled query in admin smoke test: ${sql}`);
  };

  const agent = request.agent(adminApp);

  const loginPage = await agent.get("/login");
  assert.equal(loginPage.status, 200);
  const loginCsrf = extractCsrf(loginPage.text);

  const loginRes = await agent
    .post("/login")
    .type("form")
    .send({ username: "admin", password: "secret123", _csrf: loginCsrf });

  assert.equal(loginRes.status, 302);
  assert.equal(loginRes.headers.location, "/");
  assert.ok(migratedHash);
  assert.notEqual(migratedHash, "secret123");
  assert.match(migratedHash, /^\$2/);

  const dashboardRes = await agent.get("/redirect");
  assert.equal(dashboardRes.status, 200);
  const dashboardCsrf = extractCsrf(dashboardRes.text);

  const createRes = await agent
    .post("/domains/create")
    .type("form")
    .send({
      domain_url: "https://News24h.com/some/path",
      safe_template: "age_gate",
      _csrf: dashboardCsrf,
    });

  assert.equal(createRes.status, 302);
  assert.equal(createRes.headers.location, "/redirect");
  assert.deepEqual(insertedDomain, ["news24h.com", "age_gate", 10, 10]);
});

test("admin creates an automatic redirect with a configurable delay", async () => {
  let insertedSql = "";
  let insertedParams = null;

  db.query = async (sql, params) => {
    if (sql.includes("SELECT u.*, r.name as role_name FROM users")) {
      return {
        rowCount: 1,
        rows: [
          {
            id: 11,
            username: "operator",
            password_hash: "secret123",
            role_id: 1,
            role_name: "super_admin",
          },
        ],
      };
    }
    if (sql.includes("UPDATE users SET password_hash=$1")) {
      return { rowCount: 1, rows: [] };
    }
    if (sql.includes("SELECT id, domain_url, status FROM domains")) {
      return {
        rowCount: 1,
        rows: [{ id: 5, domain_url: "wait.example", status: "active" }],
      };
    }
    if (sql.includes("FROM short_links s")) {
      return { rowCount: 0, rows: [] };
    }
    if (sql.includes("SELECT id FROM domains WHERE id=$1")) {
      return { rowCount: 1, rows: [{ id: 5 }] };
    }
    if (sql.includes("INSERT INTO short_links")) {
      insertedSql = sql;
      insertedParams = params;
      return { rowCount: 1, rows: [] };
    }
    if (sql.includes("INSERT INTO admin_audit_logs")) {
      return { rowCount: 1, rows: [] };
    }
    throw new Error(`Unhandled query in delayed link admin test: ${sql}`);
  };

  const agent = request.agent(adminApp);
  const loginPage = await agent.get("/login");
  const loginCsrf = extractCsrf(loginPage.text);
  const loginRes = await agent
    .post("/login")
    .type("form")
    .send({ username: "operator", password: "secret123", _csrf: loginCsrf });
  assert.equal(loginRes.status, 302);

  const linksPage = await agent.get("/short-links");
  assert.equal(linksPage.status, 200);
  const formCsrf = extractCsrf(linksPage.text);
  const createRes = await agent
    .post("/short-links/create")
    .type("form")
    .send({
      domain_id: "5",
      title: "Chờ 7 giây",
      target_url: "https://target.test/landing",
      code: "wait3",
      redirect_delay_seconds: "7",
      _csrf: formCsrf,
    });

  assert.equal(createRes.status, 302);
  assert.equal(createRes.headers.location, "/short-links");
  assert.match(insertedSql, /redirect_delay_seconds/);
  assert.deepEqual(insertedParams, [
    5,
    11,
    "wait3",
    "Chờ 7 giây",
    "https://target.test/landing",
    11,
    7,
  ]);
});
