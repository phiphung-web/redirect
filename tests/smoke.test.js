const test = require("node:test");
const assert = require("node:assert/strict");
const request = require("supertest");

const db = require("../src/config/db");
const adsApp = require("../src/server-ads");
const adminApp = require("../src/server-admin");

const extractCsrf = (html) => {
  const match = html.match(/name="_csrf"\s+value="([^"]+)"/);
  assert.ok(match, "missing csrf token");
  return match[1];
};

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

test("ads redirects active short link", async () => {
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
      return { rowCount: 1, rows: [] };
    }
    throw new Error(`Unhandled query in short link test: ${sql}`);
  };

  const res = await request(adsApp)
    .get("/s/Spring2026?utm_source=email")
    .set("Host", "example.com")
    .set("User-Agent", "Mozilla/5.0");

  assert.equal(res.status, 302);
  assert.equal(res.headers.location, "https://target.test/promo?utm_source=email");
  assert.equal(clickUpdated, true);
  assert.equal(trafficLogged, true);
  assert.ok(res.headers["x-request-id"]);
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

test("ads renders sanitized custom safe page template", async () => {
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
  assert.match(res.text, /Custom Safe/);
  assert.match(res.text, /\.hero \{ color: red; \}/);
  assert.doesNotMatch(res.text, /<script/i);
  assert.doesNotMatch(res.text, /onclick=/i);
  assert.doesNotMatch(res.text, /javascript:/i);
});

test("ads uses campaign safe page override when rendering safe page", async () => {
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
            safe_page_template: "custom",
            safe_page_content: {
              title: "Campaign Safe",
              headline: "Campaign Headline",
              custom_html: "<main><h1>Campaign Override</h1></main>",
              custom_css: "main{color:blue;}",
            },
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
  assert.match(res.text, /Campaign Override/);
  assert.doesNotMatch(res.text, /Domain Safe/);
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
      safe_template: "shop",
      _csrf: dashboardCsrf,
    });

  assert.equal(createRes.status, 302);
  assert.equal(createRes.headers.location, "/redirect");
  assert.deepEqual(insertedDomain, ["news24h.com", "shop", 10, 10]);
});
