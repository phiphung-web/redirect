process.env.CACHE_ENABLED = "false";
process.env.TRAFFIC_BUFFER_ENABLED = "false";
process.env.COUNTER_BUFFER_ENABLED = "false";
process.env.SESSION_STORE = "memory";
process.env.PRODUCT_NAME = "LinkPilot";
process.env.PRODUCT_SHORT_NAME = "LP";

const test = require("node:test");
const assert = require("node:assert/strict");
const request = require("supertest");
const ejs = require("ejs");
const fs = require("fs");
const path = require("path");
const vm = require("vm");

const db = require("../src/config/db");
const adsApp = require("../src/server-ads");
const adminApp = require("../src/server-admin");
const ecosystem = require("../ecosystem.config.cjs");
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

test("production PM2 profile uses a bounded redirect cluster", () => {
  const ads = ecosystem.apps.find((app) => app.name === "linkpilot-ads");
  const admin = ecosystem.apps.find((app) => app.name === "linkpilot-admin");
  assert.equal(ads.exec_mode, "cluster");
  assert.equal(ads.instances, 4);
  assert.equal(admin.exec_mode, "fork");
  assert.equal(admin.instances, 1);
});

test("product exposes exactly the two fixed safe page templates", () => {
  assert.deepEqual([...SAFE_TEMPLATES], ["clean", "age_gate"]);
  assert.equal(normalizeSafeTemplate("age_gate"), "age_gate");
  assert.equal(normalizeSafeTemplate("custom"), "clean");
  assert.deepEqual(
    fs.readdirSync(path.join(__dirname, "../src/views/safepages")).sort(),
    ["age_gate.ejs", "clean.ejs"]
  );
});

test("safe pages are English-only and selected only when adding a domain", () => {
  const viewsRoot = path.join(__dirname, "../src/views");
  const clean = fs.readFileSync(path.join(viewsRoot, "safepages/clean.ejs"), "utf8");
  const ageGate = fs.readFileSync(
    path.join(viewsRoot, "safepages/age_gate.ejs"),
    "utf8"
  );
  const dashboard = fs.readFileSync(
    path.join(viewsRoot, "admin/dashboard.ejs"),
    "utf8"
  );
  const domainDetail = fs.readFileSync(
    path.join(viewsRoot, "admin/domain_detail.ejs"),
    "utf8"
  );
  const campaignEdit = fs.readFileSync(
    path.join(viewsRoot, "admin/campaign_edit.ejs"),
    "utf8"
  );
  const vietnameseCharacters = /[ăâđêôơưĂÂĐÊÔƠƯàáạảãầấậẩẫằắặẳẵèéẹẻẽềếệểễìíịỉĩòóọỏõồốộổỗờớợởỡùúụủũừứựửữỳýỵỷỹ]/i;

  assert.match(clean, /<html lang="en">/);
  assert.match(clean, /Repair and Maintenance Services/);
  assert.match(clean, /safe-repair-hero\.png/);
  assert.match(clean, /safe-repair-about\.jpg/);
  assert.doesNotMatch(clean, vietnameseCharacters);
  assert.match(ageGate, /<html lang="en">/);
  assert.doesNotMatch(ageGate, vietnameseCharacters);
  assert.match(dashboard, /name="safe_template"/);
  assert.equal((dashboard.match(/<option value="(?:clean|age_gate)"/g) || []).length, 2);
  assert.doesNotMatch(domainDetail, /action="\/domains\/<%= domain\.id %>\/safe-content"/);
  assert.doesNotMatch(domainDetail, /Lưu Safe Page/);
  assert.doesNotMatch(domainDetail, /campaignSafePageSelect/);
  assert.doesNotMatch(campaignEdit, /name="safe_template"/);
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
    sslAutomationEnabled: false,
  });
  const domainDetail = await ejs.renderFile(
    path.join(views, "domain_detail.ejs"),
    {
      product,
      csrfToken: "test-token",
      user,
      domain: {
        id: 1,
        domain_url: "example.com",
        safe_template: "clean",
        status: "active",
        ssl_status: "fallback",
        ssl_error: null,
        ssl_expires_at: null,
        created_at: new Date().toISOString(),
      },
      links: [],
      shortLinks: [],
      linkStats: { total: 0, active: 0 },
      domainTrafficStats: {
        link_traffic: 0,
        safe_page_views: 0,
        direct_or_unmatched: 0,
      },
      sslAutomationEnabled: false,
    }
  );
  const delayedSafePage = await ejs.renderFile(
    path.join(__dirname, "../src/views/safepages/clean.ejs"),
    {
      title: "example.com",
      domain: "example.com",
      redirectTargetUrl: "https://target.test/landing?utm_source=email",
      redirectDelaySeconds: 3,
    }
  );
  assert.match(login, /Chào mừng trở lại/);
  assert.match(welcome, /Hai luồng redirect/);
  assert.match(dashboard, /Chưa có domain nào/);
  assert.match(domainDetail, /data-create-link-type="conditional"/);
  assert.match(domainDetail, /data-create-link-type="delayed"/);
  assert.match(domainDetail, /src="\/domains\/1\/safe-preview"/);
  assert.match(delayedSafePage, /Repair &amp; Maintenance Services/);
  assert.match(delayedSafePage, /const delayMs = 3000/);
  assert.match(delayedSafePage, /https:\/\/target\.test\/landing\?utm_source=email/);
  assert.doesNotMatch(delayedSafePage, /countdown|Continue now/i);
});

test("domain link builder keeps tracking presets clean and exposes both flows", () => {
  const source = fs.readFileSync(
    path.join(__dirname, "../src/views/admin/domain_detail.ejs"),
    "utf8"
  );
  assert.doesNotMatch(source, /fbclid|fbcid/i);
  assert.match(source, /key: 'campaign_id', operator: 'exists'/);
  assert.match(source, /sampleValue: '{{campaign\.id}}'/);
  assert.doesNotMatch(source, /campaign_id=xxx|: 'xxx'/);
  assert.match(source, /data-link-type="conditional"/);
  assert.match(source, /data-link-type="delayed"/);
  assert.match(source, /form\.action = isConditional \? '\/campaigns\/create' : '\/short-links\/create'/);
  assert.doesNotMatch(source, /escapeAttr\(/);
  const inlineScripts = [...source.matchAll(/<script>([\s\S]*?)<\/script>/g)];
  assert.ok(inlineScripts.length > 0);
  inlineScripts.forEach((match) => assert.doesNotThrow(() => new vm.Script(match[1])));
});

test("admin analytics separate successful link traffic from raw safe-page requests", () => {
  const serverSource = fs.readFileSync(
    path.join(__dirname, "../src/server-admin.js"),
    "utf8"
  );
  const dashboardSource = fs.readFileSync(
    path.join(__dirname, "../src/views/admin/dashboard.ejs"),
    "utf8"
  );
  const domainSource = fs.readFileSync(
    path.join(__dirname, "../src/views/admin/domain_detail.ejs"),
    "utf8"
  );

  assert.match(serverSource, /action IN \('redirect', 'short_redirect'\)/);
  assert.match(serverSource, /action LIKE 'safe_page%'/);
  assert.match(dashboardSource, /Lượt qua link/);
  assert.match(dashboardSource, /Không tính Safe Page\/probe/);
  assert.match(domainSource, /direct_or_unmatched/);
  assert.match(domainSource, /log_redirects/);
  assert.match(domainSource, /log_clicks/);
});

test("contextual help is available across the admin product", () => {
  const viewsRoot = path.join(__dirname, "../src/views");
  const adminRoot = path.join(viewsRoot, "admin");
  const criticalViews = [
    "dashboard.ejs",
    "domain_detail.ejs",
    "campaign_edit.ejs",
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

test("exists rules check only the key while equals rules check the value", async () => {
  db.query = async (sql) => {
    if (sql.includes("FROM domains WHERE domain_url")) {
      return {
        rowCount: 1,
        rows: [
          {
            id: 31,
            domain_url: "exists-rule.example",
            status: "active",
            safe_template: "clean",
          },
        ],
      };
    }
    if (sql.includes("FROM campaigns c")) {
      return {
        rowCount: 1,
        rows: [
          {
            id: 32,
            domain_id: 31,
            is_active: true,
            filters: {},
            rules: [
              { key: "campaign_id", operator: "exists", value: "" },
              { key: "utm_source", operator: "equals", value: "facebook" },
            ],
            target_url: "https://target.test/rules",
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
    throw new Error(`Unhandled query in rule semantics test: ${sql}`);
  };

  const res = await request(adsApp)
    .get("/?q=rule32&utm_source=facebook&campaign_id")
    .set("Host", "exists-rule.example")
    .set("User-Agent", "Mozilla/5.0");

  assert.equal(res.status, 302);
  assert.match(res.headers.location, /campaign_id=/);
  assert.match(res.headers.location, /utm_source=facebook/);

  const wrongValue = await request(adsApp)
    .get("/?q=rule32&utm_source=google&campaign_id")
    .set("Host", "exists-rule.example")
    .set("User-Agent", "Mozilla/5.0");
  assert.equal(wrongValue.status, 200);
  assert.match(wrongValue.text, /Repair and Maintenance Services/);
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
  assert.match(res.text, /Repair and Maintenance Services/);
  assert.match(res.text, /const delayMs = 3000/);
  assert.match(res.text, /https:\/\/target\.test\/promo\?utm_source=email/);
  assert.doesNotMatch(res.text, /countdown|Continue now/i);
  assert.equal(clickUpdated, true);
  assert.equal(trafficLogged, true);
  assert.ok(res.headers["x-request-id"]);
});

test("ads keeps the domain safe page visible and redirects silently", async () => {
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
  assert.match(res.text, /Repair and Maintenance Services/);
  assert.match(res.text, /const delayMs = 3000/);
  assert.match(res.text, /utm_source=email/);
  assert.match(res.text, /campaign_id=sale/);
  assert.doesNotMatch(res.text, /countdown|Continue now/i);
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
  assert.match(res.text, /Repair and Maintenance Services/);
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
  assert.match(res.text, /Repair and Maintenance Services/);
  assert.match(res.text, /safe-repair-hero\.png/);
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
  assert.match(res.text, /Repair and Maintenance Services/);
  assert.doesNotMatch(res.text, /Custom Safe/);
  assert.doesNotMatch(res.text, /<script/i);
  assert.doesNotMatch(res.text, /onclick=/i);
  assert.doesNotMatch(res.text, /javascript:/i);
});

test("ads ignores deprecated campaign safe-page overrides", async () => {
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
  assert.match(res.text, /Repair and Maintenance Services/);
  assert.match(res.text, /safe-repair-hero\.png/);
  assert.doesNotMatch(res.text, /safe-age-gate\.jpeg/);
});

test("redirect engine serves the bundled age-gate image", async () => {
  const res = await request(adsApp).get("/assets/images/safe-age-gate.jpeg");
  assert.equal(res.status, 200);
  assert.match(res.headers["content-type"], /^image\/jpeg/);
  assert.ok(Number(res.headers["content-length"] || res.body.length) > 40000);
});

test("redirect engine serves the bundled repair-page images", async () => {
  const hero = await request(adsApp).get("/assets/images/safe-repair-hero.png");
  const about = await request(adsApp).get("/assets/images/safe-repair-about.jpg");
  assert.equal(hero.status, 200);
  assert.match(hero.headers["content-type"], /^image\/png/);
  assert.ok(Number(hero.headers["content-length"] || hero.body.length) > 300000);
  assert.equal(about.status, 200);
  assert.match(about.headers["content-type"], /^image\/jpeg/);
  assert.ok(Number(about.headers["content-length"] || about.body.length) > 80000);
});

test("automatic SSL uses a constrained Certbot helper and tracked domain state", () => {
  const root = path.join(__dirname, "..");
  const provisioner = fs.readFileSync(
    path.join(root, "src/services/ssl-provisioner.js"),
    "utf8"
  );
  const helper = fs.readFileSync(
    path.join(root, "deploy/provision-domain-ssl.sh"),
    "utf8"
  );
  const migration = fs.readFileSync(
    path.join(root, "database/migrations/2026-07-21-zzz-domain-auto-ssl.sql"),
    "utf8"
  );
  const nginx = fs.readFileSync(
    path.join(root, "deploy/nginx.contabo.conf"),
    "utf8"
  );

  assert.match(provisioner, /execFileAsync\(ssl\.command, \[domain\.domain_url\]/);
  assert.doesNotMatch(provisioner, /\bexec\s*\(/);
  assert.match(helper, /Invalid domain name/);
  assert.match(helper, /LETSENCRYPT_AGREE_TOS=true is required/);
  assert.match(helper, /certbot certonly/);
  assert.match(helper, /--webroot/);
  assert.match(helper, /nginx -t/);
  assert.doesNotMatch(helper, /\beval\b/);
  assert.match(migration, /ssl_status/);
  assert.match(migration, /ssl_expires_at/);
  assert.match(nginx, /\.well-known\/acme-challenge/);
  assert.match(nginx, /listen 443 ssl default_server/);
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
      return { rowCount: 1, rows: [{ id: 42 }] };
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
  assert.equal(createRes.headers.location, "/domains/42");
  assert.deepEqual(insertedDomain, [
    "news24h.com",
    "age_gate",
    10,
    10,
    "fallback",
  ]);
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

  const homePage = await agent.get("/");
  assert.equal(homePage.status, 200);
  const formCsrf = extractCsrf(homePage.text);
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
  assert.equal(createRes.headers.location, "/domains/5");
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

test("admin creates a conditional link with submitted quick-template rules", async () => {
  let insertedParams = null;

  db.query = async (sql, params) => {
    if (sql.includes("SELECT u.*, r.name as role_name FROM users")) {
      return {
        rowCount: 1,
        rows: [{ id: 12, username: "builder", password_hash: "secret123", role_id: 1, role_name: "super_admin" }],
      };
    }
    if (sql.includes("UPDATE users SET password_hash=$1")) return { rowCount: 1, rows: [] };
    if (sql.includes("SELECT 1 FROM campaigns WHERE domain_id")) return { rowCount: 0, rows: [] };
    if (sql.includes("INSERT INTO campaigns")) {
      insertedParams = params;
      return { rowCount: 1, rows: [] };
    }
    if (sql.includes("INSERT INTO admin_audit_logs")) return { rowCount: 1, rows: [] };
    throw new Error(`Unhandled query in conditional link admin test: ${sql}`);
  };

  const agent = request.agent(adminApp);
  const loginPage = await agent.get("/login");
  const loginCsrf = extractCsrf(loginPage.text);
  await agent
    .post("/login")
    .type("form")
    .send({ username: "builder", password: "secret123", _csrf: loginCsrf });

  const welcome = await agent.get("/");
  const formCsrf = extractCsrf(welcome.text);
  const rules = [
    { key: "utm_source", operator: "equals", value: "facebook" },
    { key: "campaign_id", operator: "exists", value: "" },
  ];
  const createRes = await agent
    .post("/campaigns/create")
    .type("form")
    .send({
      domain_id: "9",
      name: "Facebook campaign",
      target_url: "https://target.test/landing",
      rules_json: JSON.stringify(rules),
      allowed_countries: ["US"],
      _csrf: formCsrf,
    });

  assert.equal(createRes.status, 302);
  assert.equal(createRes.headers.location, "/domains/9");
  assert.ok(insertedParams);
  assert.deepEqual(JSON.parse(insertedParams[6]), rules);
  assert.deepEqual(JSON.parse(insertedParams[7]), { countries: ["US"] });
});
