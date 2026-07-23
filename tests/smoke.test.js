process.env.CACHE_ENABLED = "false";
process.env.TRAFFIC_BUFFER_ENABLED = "false";
process.env.COUNTER_BUFFER_ENABLED = "false";
process.env.SESSION_STORE = "memory";
process.env.AUTO_SSL_ENABLED = "false";
process.env.PRODUCT_NAME = "LinkPilot";
process.env.PRODUCT_SHORT_NAME = "LP";

const test = require("node:test");
const assert = require("node:assert/strict");
const request = require("supertest");
const ejs = require("ejs");
const fs = require("fs");
const path = require("path");
const vm = require("vm");
const root = path.join(__dirname, "..");

const db = require("../src/config/db");
const adsApp = require("../src/server-ads");
const adminApp = require("../src/server-admin");
const ecosystem = require("../ecosystem.config.cjs");
const {
  SAFE_TEMPLATES,
  normalizeSafeTemplate,
  parseRules,
} = require("../src/utils/validation");
const { hashConnectCode, parseCommand } = require("../src/services/telegram-bot");
const {
  groupRuleFailuresByUser,
  inspectLinkConfiguration,
  parseRuleFailureDetail,
} = require("../scripts/monitor-system");

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
  assert.ok(Number.isInteger(ads.instances));
  assert.ok(ads.instances >= 1 && ads.instances <= 6);
  if (Number.isInteger(Number.parseInt(process.env.ADS_INSTANCES, 10))) {
    assert.equal(
      ads.instances,
      Math.min(Math.max(Number.parseInt(process.env.ADS_INSTANCES, 10), 1), 6)
    );
  }
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

test("owner branch keeps two roles and private seven-day audit retention", () => {
  const rolesMigration = fs.readFileSync(
    path.join(root, "database/migrations/2026-07-22-two-user-roles.sql"),
    "utf8"
  );
  const telegramMigration = fs.readFileSync(
    path.join(root, "database/migrations/2026-07-22-user-telegram-links.sql"),
    "utf8"
  );
  const auditService = fs.readFileSync(
    path.join(root, "src/services/file-audit.js"),
    "utf8"
  );
  assert.match(rolesMigration, /\('super_admin'/);
  assert.match(rolesMigration, /\('user'/);
  assert.match(
    rolesMigration,
    /DELETE FROM public\.roles WHERE name NOT IN \('super_admin', 'user'\)/
  );
  assert.match(telegramMigration, /telegram_chat_id/);
  assert.match(auditService, /AUDIT_RETENTION_DAYS \|\| "7"/);
  assert.doesNotMatch(auditService, /req\.body/);
});

test("domain access keeps its creator as owner and only shares with regular users", () => {
  const migration = fs.readFileSync(
    path.join(
      root,
      "database/migrations/2026-07-23-domain-user-access.sql"
    ),
    "utf8"
  );
  const adminSource = fs.readFileSync(
    path.join(root, "src/server-admin.js"),
    "utf8"
  );
  const domainView = fs.readFileSync(
    path.join(root, "src/views/admin/domain_detail.ejs"),
    "utf8"
  );
  const cleanup = fs.readFileSync(
    path.join(root, "scripts/cleanup-traffic.js"),
    "utf8"
  );
  const trafficArchiveMigration = fs.readFileSync(
    path.join(
      root,
      "database/migrations/2026-07-23-traffic-daily-short-links.sql"
    ),
    "utf8"
  );
  const trafficDimensionMigration = fs.readFileSync(
    path.join(
      root,
      "database/migrations/2026-07-23-zzzz-traffic-report-dimensions.sql"
    ),
    "utf8"
  );
  const sharingPolicyMigration = fs.readFileSync(
    path.join(
      root,
      "database/migrations/2026-07-23-zz-domain-sharing-policy.sql"
    ),
    "utf8"
  );

  assert.match(migration, /CREATE TABLE IF NOT EXISTS public\.domain_user_access/);
  assert.match(migration, /idx_domain_user_access_one_owner/);
  assert.match(migration, /migration\.domain_user_access\.legacy_owner_v1/);
  assert.match(migration, /UPDATE public\.domains[\s\S]+SET user_id=super_admin_id/);
  assert.match(migration, /UPDATE public\.campaigns[\s\S]+SET user_id=super_admin_id/);
  assert.match(migration, /UPDATE public\.short_links[\s\S]+SET user_id=super_admin_id/);
  assert.match(adminSource, /FROM domain_user_access[\s\S]+WHERE domain_id=\$1 AND user_id=\$2/);
  assert.match(adminSource, /"\/domains\/:id\/access"/);
  assert.doesNotMatch(domainView, /owner_user_id/);
  assert.match(domainView, /member_user_ids/);
  assert.match(adminSource, /const isOwner = Number\(domain\.user_id\)/);
  assert.match(adminSource, /r\.name='user'/);
  assert.match(domainView, /viewerCanManageAccess/);
  assert.match(domainView, /không thể chia sẻ tiếp/);
  assert.match(sharingPolicyMigration, /r\.name='super_admin'/);
  assert.match(sharingPolicyMigration, /dua\.access_level='member'/);
  assert.match(cleanup, /DELETE FROM traffic_logs/);
  assert.match(cleanup, /DELETE FROM admin_audit_logs/);
  assert.match(cleanup, /short_link_id/);
  assert.match(cleanup, /country,[\s\S]*device_type,[\s\S]*hits/);
  assert.match(trafficArchiveMigration, /PRIMARY KEY \(day, domain_id, campaign_id, short_link_id, action\)/);
  assert.match(trafficDimensionMigration, /ADD COLUMN IF NOT EXISTS country/);
  assert.match(trafficDimensionMigration, /ADD COLUMN IF NOT EXISTS device_type/);
  assert.match(
    trafficDimensionMigration,
    /PRIMARY KEY \([\s\S]*country,[\s\S]*device_type[\s\S]*\)/
  );
  assert.match(adminSource, /FROM traffic_daily_stats/);
});

test("user administration supports safe edit, reset, delete, and restore", () => {
  const adminSource = fs.readFileSync(
    path.join(root, "src/server-admin.js"),
    "utf8"
  );
  const detailView = fs.readFileSync(
    path.join(root, "src/views/admin/user_detail.ejs"),
    "utf8"
  );
  const listView = fs.readFileSync(
    path.join(root, "src/views/admin/users_list.ejs"),
    "utf8"
  );

  assert.match(adminSource, /"\/users\/view\/:id\/update"/);
  assert.match(adminSource, /requestedPassword\.length < 6/);
  assert.match(adminSource, /Phải giữ lại ít nhất một super admin/);
  assert.match(adminSource, /DELETE FROM domain_user_access[\s\S]+access_level='member'/);
  assert.match(adminSource, /UPDATE projects[\s\S]+WHERE user_id=\$1/);
  assert.match(detailView, /name="username"/);
  assert.match(detailView, /name="new_password"/);
  assert.match(detailView, /name="is_active"/);
  assert.match(detailView, /Xóa user/);
  assert.match(listView, /Xem \/ khôi phục/);
});

test("projects organize links across domains without changing legacy links", () => {
  const migration = fs.readFileSync(
    path.join(
      root,
      "database/migrations/2026-07-23-project-management.sql"
    ),
    "utf8"
  );
  const accessMigration = fs.readFileSync(
    path.join(
      root,
      "database/migrations/2026-07-23-zzz-project-user-access.sql"
    ),
    "utf8"
  );
  const adminSource = fs.readFileSync(
    path.join(root, "src/server-admin.js"),
    "utf8"
  );
  const header = fs.readFileSync(
    path.join(root, "src/views/partials/header.ejs"),
    "utf8"
  );
  const domainDetail = fs.readFileSync(
    path.join(root, "src/views/admin/domain_detail.ejs"),
    "utf8"
  );

  assert.match(migration, /CREATE TABLE IF NOT EXISTS public\.projects/);
  assert.match(accessMigration, /CREATE TABLE IF NOT EXISTS public\.project_user_access/);
  assert.match(accessMigration, /access_level = 'viewer'/);
  assert.match(migration, /ADD COLUMN IF NOT EXISTS project_id/);
  assert.match(migration, /ON DELETE SET NULL/);
  assert.match(adminSource, /app\.get\("\/projects", checkAuth/);
  assert.match(adminSource, /"\/projects\/:id"/);
  assert.match(adminSource, /projectScopeUserId/);
  assert.match(adminSource, /"\/projects\/:id\/access"/);
  assert.match(adminSource, /FROM project_user_access pua/);
  assert.match(adminSource, /requireProjectAccess\(\{ manage: true \}\)/);
  assert.match(header, /href="\/projects"/);
  assert.match(domainDetail, /name="project_id"/);
  assert.match(domainDetail, /Chưa phân loại/);
});

test("Telegram codes and link configuration checks are deterministic", () => {
  assert.deepEqual(parseCommand("/connect ABC-123"), {
    command: "connect",
    argument: "ABC-123",
  });
  assert.equal(hashConnectCode(" abc "), hashConnectCode("ABC"));
  assert.deepEqual(
    inspectLinkConfiguration(
      { id: 7, target_url: "bad-url", rules: [] },
      "Link điều kiện"
    ),
    [
      "Link điều kiện #7: URL đích không hợp lệ",
      "Link điều kiện #7: chưa có rule kiểm tra",
    ]
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
  assert.match(domainDetail, /Mở Safe Page/);
  assert.doesNotMatch(domainDetail, /<iframe[^>]+safe-preview/);
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
  assert.doesNotMatch(source, /data-rule-template=/);
  assert.match(source, /key: 'utm_source', operator: 'equals', value: ''/);
  assert.match(source, /key: 'utm_medium', operator: 'equals', value: ''/);
  assert.match(source, /key: 'utm_campaign', operator: 'equals', value: ''/);
  assert.match(source, /key: 'utm_content', operator: 'equals', value: ''/);
  assert.doesNotMatch(source, /key: 'utm_id'|key: 'campaign_id'|key: 'gclid'|key: 'ttclid'/);
  assert.doesNotMatch(source, /value: '(?:kalite|sds|dsd)'/);
  assert.match(source, /valueInput\.required = operator\.value === 'equals'/);
  assert.match(source, /COPY_EXCLUDED_RULE_KEYS = new Set\(\['fbclid', 'fbcid'\]\)/);
  assert.match(source, /COPY_EXCLUDED_RULE_KEYS\.has\(key\.toLowerCase\(\)\)/);
  assert.match(source, /replaceAll\('%7B', '{'\)\.replaceAll\('%7D', '}'\)/);
  assert.match(source, /if \(!value\) return \[\]/);
  assert.doesNotMatch(source, /campaign_id=xxx|: 'xxx'/);
  assert.match(source, /data-link-type="conditional"/);
  assert.match(source, /data-link-type="delayed"/);
  assert.match(source, /form\.action = isConditional \? '\/campaigns\/create' : '\/short-links\/create'/);
  assert.doesNotMatch(source, /name="code"/);
  assert.match(source, /Đường dẫn ngắn sẽ được hệ thống tự sinh/);
  assert.doesNotMatch(source, /data-simple-param|advancedConditionalSettings/);
  assert.match(source, /if \(isConditional && !document\.querySelector\('#rules-wrapper \.rule-row'\)\) \{\s*addTemplate\('fb_custom'\)/);
  assert.match(source, /if \(key\.toLowerCase\(\) === 'fbclid'\) \{\s*return \[\{ key: 'fbclid', operator: 'exists', value: '' \}\]/);
  assert.match(source, /return configurableRules/);
  assert.match(source, /fb_custom: \[\s*\{ key: 'fbclid', operator: 'exists', value: '' \}/);
  assert.match(source, /row\.dataset\.systemRule = isSystemRule \? 'true' : 'false'/);
  assert.match(source, /keyInput\.readOnly = true/);
  assert.match(source, /operator\.disabled = true/);
  assert.match(source, /remove\.title = 'Xóa kiểm tra fbclid'/);
  assert.doesNotMatch(source, /remove\.disabled = true/);
  assert.doesNotMatch(source, /row\.classList\.toggle\('d-none'/);
  assert.match(source, /copyValueInput\.type = 'hidden'/);
  assert.doesNotMatch(source, /copyValueInput\.placeholder|Giá trị URL Ads/);
  assert.match(source, /id="copyGeneratedParamsButton"/);
  assert.match(source, /id="copyGeneratedParamsStatus"/);
  assert.match(source, /Đã sao chép — dán vào mục Thông số URL của quảng cáo/);
  assert.doesNotMatch(source, /alert\("Đã copy chuỗi tham số"\)/);
  assert.doesNotMatch(source, /escapeAttr\(/);
  const inlineScripts = [...source.matchAll(/<script>([\s\S]*?)<\/script>/g)];
  assert.ok(inlineScripts.length > 0);
  inlineScripts.forEach((match) => assert.doesNotThrow(() => new vm.Script(match[1])));

  assert.deepEqual(
    parseRules([
      { key: "campaign_id", operator: "exists", value: "", copyValue: "{{campaign.id}}" },
    ]),
    [
      { key: "campaign_id", operator: "exists", value: "", copyValue: "{{campaign.id}}" },
    ]
  );

  const editSource = fs.readFileSync(
    path.join(__dirname, "../src/views/admin/campaign_edit.ejs"),
    "utf8"
  );
  assert.match(editSource, /SYSTEM_RULE_KEYS = new Set\(\['fbclid', 'fbcid'\]\)/);
  assert.match(editSource, /oldRules\.forEach\(r => addNewRule\(r\.key, r\.operator, r\.value, r\.copyValue\)\)/);
  assert.match(editSource, /row\.attr\('data-system-rule', 'true'\)/);
  assert.match(editSource, /\.prop\('readonly', true\)/);
  assert.match(editSource, /\.val\('exists'\)\.prop\('disabled', true\)/);
  assert.match(editSource, /Xóa kiểm tra fbclid/);
  assert.match(editSource, /const rules = \[\]/);
  assert.match(editSource, /if \(normalizedKey === 'fbclid'\) \{\s*rules\.push\(\{ key: 'fbclid', operator: 'exists', value: '' \}\)/);
  assert.match(editSource, /type="hidden" class="rule-copy-val"/);
  assert.doesNotMatch(editSource, /Giá trị URL Ads/);
  assert.match(source, /\/images\/meta-url-parameters-guide\.svg/);
  assert.match(source, /Dán chuỗi ở đâu\?/);
});

test("report time filters keep labels outside controls", () => {
  const report = fs.readFileSync(path.join(__dirname, "../src/views/admin/report_v2.ejs"), "utf8");
  const shortReport = fs.readFileSync(path.join(__dirname, "../src/views/admin/short_link_report.ejs"), "utf8");
  const serverSource = fs.readFileSync(
    path.join(__dirname, "../src/server-admin.js"),
    "utf8"
  );
  const campaignLogs = fs.readFileSync(
    path.join(__dirname, "../src/views/admin/logs.ejs"),
    "utf8"
  );
  const shortLinkLogs = fs.readFileSync(
    path.join(__dirname, "../src/views/admin/short_link_logs.ejs"),
    "utf8"
  );
  [report, shortReport].forEach((source) => {
    assert.match(source, /class="report-filter-field"/);
    assert.doesNotMatch(source, /class="form-floating/);
  });
  assert.match(serverSource, /SELECT generate_series\(/);
  assert.match(serverSource, /LEFT JOIN aggregated USING \(bucket\)/);
  assert.match(serverSource, /action LIKE 'safe_page%'/);
  assert.match(serverSource, /ip::text=\$/);
  [campaignLogs, shortLinkLogs].forEach((source) => {
    assert.match(source, /name="country"/);
    assert.match(source, /name="device"/);
    assert.match(source, /name="ip"/);
    assert.match(source, /paginationQuery/);
  });
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
  const campaignReportSource = fs.readFileSync(
    path.join(__dirname, "../src/views/admin/report_v2.ejs"),
    "utf8"
  );

  assert.match(serverSource, /action IN \('redirect', 'short_redirect_confirmed'\)/);
  assert.match(serverSource, /action LIKE 'safe_page%'/);
  assert.match(dashboardSource, /Lượt qua link/);
  assert.match(dashboardSource, /Không tính Safe Page\/probe/);
  assert.match(domainSource, /direct_or_unmatched/);
  assert.match(domainSource, /log_redirects/);
  assert.match(domainSource, /confirmed_redirects/);
  assert.match(domainSource, /opened_count/);
  assert.match(
    serverSource,
    /SELECT device_type,[\s\S]*SUM\(redirects\)::bigint AS redirects,[\s\S]*SUM\(hits\)::bigint AS hits/
  );
  assert.match(serverSource, /deviceStats: deviceStats\.rows/);
  assert.match(campaignReportSource, /deviceStats && deviceStats\.forEach/);
  assert.match(campaignReportSource, />Hit<[\s\S]*>Pass</);
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

test("rule-failure traffic alerts explain and group near-miss requests", () => {
  assert.equal(
    parseRuleFailureDetail(
      "safe_page_missing_param",
      "url=https://safe.test | detail=missing:fbclid"
    ),
    "Thiếu tham số fbclid"
  );
  assert.equal(
    parseRuleFailureDetail(
      "safe_page_wrong_param_val",
      "detail=expect utm_source=facebook; got=google"
    ),
    'Sai utm_source: cần "facebook", nhận "google"'
  );

  const grouped = groupRuleFailuresByUser([
    {
      campaign_id: 9,
      campaign_name: "Meta Ads",
      domain_url: "safe.test",
      action: "safe_page_missing_param",
      referer: "detail=missing:fbclid",
      user_ids: [1, 7],
    },
    {
      campaign_id: 9,
      campaign_name: "Meta Ads",
      domain_url: "safe.test",
      action: "safe_page_missing_param",
      referer: "detail=missing:fbclid",
      user_ids: [1],
    },
  ]);
  assert.equal(grouped.get("1").values().next().value.count, 2);
  assert.equal(grouped.get("7").values().next().value.count, 1);
});

test("users have a self-service profile and six-character password minimum", () => {
  const root = path.join(__dirname, "..");
  const server = fs.readFileSync(path.join(root, "src/server-admin.js"), "utf8");
  const detail = fs.readFileSync(
    path.join(root, "src/views/admin/user_detail.ejs"),
    "utf8"
  );
  const users = fs.readFileSync(
    path.join(root, "src/views/admin/users_list.ejs"),
    "utf8"
  );
  const header = fs.readFileSync(
    path.join(root, "src/views/partials/header.ejs"),
    "utf8"
  );

  assert.match(server, /app\.get\("\/account\/profile", checkAuth/);
  assert.match(server, /app\.post\("\/account\/password", checkAuth/);
  assert.match(server, /newPassword\.length < 6/);
  assert.match(detail, /action="\/account\/password"/);
  assert.match(detail, /href="\/account\/telegram"/);
  assert.match(users, /minlength="6"/);
  assert.match(header, /href="\/account\/profile"/);
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

test("ads records a short-link open without counting a redirect before the timer", async () => {
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
      assert.equal(params[8], "short_link_open");
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
  assert.match(res.text, /navigator\.sendBeacon/);
  assert.match(res.text, /\/s\/spring2026\/confirm/);
  assert.match(res.text, /https:\/\/target\.test\/promo\?utm_source=email/);
  assert.doesNotMatch(res.text, /countdown|Continue now/i);
  assert.equal(clickUpdated, false);
  assert.equal(trafficLogged, true);
  assert.ok(res.headers["x-request-id"]);
});

test("ads counts a delayed redirect only after a signed browser confirmation", async () => {
  let visitId = null;
  let confirmed = false;
  let clickUpdates = 0;

  db.query = async (sql, params) => {
    if (sql.includes("FROM domains WHERE domain_url")) {
      return {
        rowCount: 1,
        rows: [{ id: 8, domain_url: "confirm.example", status: "active" }],
      };
    }
    if (sql.includes("FROM short_links")) {
      return {
        rowCount: 1,
        rows: [{
          id: 33,
          domain_id: 8,
          code: "confirm1",
          is_active: true,
          redirect_delay_seconds: 1,
          target_url: "https://target.test/confirmed",
        }],
      };
    }
    if (sql.includes("INSERT INTO traffic_logs")) {
      assert.equal(params[8], "short_link_open");
      visitId = params[11];
      return { rowCount: 1, rows: [] };
    }
    if (sql.includes("SET action='short_redirect_confirmed'")) {
      assert.deepEqual(params, [visitId, 33, 8]);
      if (confirmed) return { rowCount: 0, rows: [] };
      confirmed = true;
      return { rowCount: 1, rows: [{ id: 1 }] };
    }
    if (sql.includes("UPDATE short_links SET clicks")) {
      clickUpdates += 1;
      return { rowCount: 1, rows: [] };
    }
    throw new Error(`Unhandled query in confirmed short-link test: ${sql}`);
  };

  const open = await request(adsApp)
    .get("/s/confirm1")
    .set("Host", "confirm.example")
    .set("User-Agent", "Mozilla/5.0");
  assert.equal(open.status, 200);
  assert.equal(clickUpdates, 0);

  const tokenMatch = open.text.match(/const confirmToken = ("[^"]+")/);
  assert.ok(tokenMatch, "missing signed redirect confirmation token");
  const token = JSON.parse(tokenMatch[1]);
  const payload = JSON.parse(Buffer.from(token.split(".")[0], "base64url").toString("utf8"));
  const realDateNow = Date.now;
  Date.now = () => payload.notBefore;
  try {
    const confirm = await request(adsApp)
      .post("/s/confirm1/confirm")
      .set("Host", "confirm.example")
      .send({ token });
    assert.equal(confirm.status, 204);

    const duplicate = await request(adsApp)
      .post("/s/confirm1/confirm")
      .set("Host", "confirm.example")
      .send({ token });
    assert.equal(duplicate.status, 204);
  } finally {
    Date.now = realDateNow;
  }

  assert.equal(confirmed, true);
  assert.equal(clickUpdates, 1);
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
  assert.match(helper, /ADS_PORT must be a valid TCP port/);
  assert.match(helper, /proxy_pass http:\/\/127\.0\.0\.1:\$\{ads_port\}/);
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

test("admin creates an automatic redirect with a generated short code", async () => {
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
  assert.equal(insertedParams[0], 5);
  assert.equal(insertedParams[1], 11);
  assert.match(insertedParams[2], /^[a-z0-9]{10}$/);
  assert.notEqual(insertedParams[2], "wait3");
  assert.deepEqual(insertedParams.slice(3), [
    "Chờ 7 giây",
    "https://target.test/landing",
    11,
    7,
    null,
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
    { key: "campaign_id", operator: "exists", value: "", copyValue: "{{campaign.id}}" },
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
  assert.equal(insertedParams[9], null);
});

test("an authenticated user can create a cross-domain project", async () => {
  let insertedProject = null;
  db.query = async (sql, params) => {
    if (sql.includes("SELECT u.*, r.name as role_name FROM users")) {
      return {
        rowCount: 1,
        rows: [
          {
            id: 21,
            username: "project-owner",
            password_hash: "secret123",
            role_id: 2,
            role_name: "user",
          },
        ],
      };
    }
    if (sql.includes("UPDATE users SET password_hash=$1")) {
      return { rowCount: 1, rows: [] };
    }
    if (sql.includes("INSERT INTO projects")) {
      insertedProject = params;
      return { rowCount: 1, rows: [{ id: 31 }] };
    }
    if (sql.includes("INSERT INTO admin_audit_logs")) {
      return { rowCount: 1, rows: [] };
    }
    throw new Error(`Unhandled query in project create test: ${sql}`);
  };

  const agent = request.agent(adminApp);
  const loginPage = await agent.get("/login");
  const loginCsrf = extractCsrf(loginPage.text);
  await agent
    .post("/login")
    .type("form")
    .send({
      username: "project-owner",
      password: "secret123",
      _csrf: loginCsrf,
    });
  const welcome = await agent.get("/");
  const csrf = extractCsrf(welcome.text);
  const response = await agent
    .post("/projects/create")
    .type("form")
    .send({
      name: "Khách hàng A",
      description: "Link từ nhiều domain",
      _csrf: csrf,
    });

  assert.equal(response.status, 302);
  assert.equal(response.headers.location, "/projects/31");
  assert.deepEqual(insertedProject, [
    21,
    "Khách hàng A",
    "Link từ nhiều domain",
  ]);
});

test("a project viewer sees only project links and cannot manage them", async () => {
  db.query = async (sql, params = []) => {
    if (sql.includes("SELECT u.*, r.name as role_name FROM users")) {
      return {
        rowCount: 1,
        rows: [
          {
            id: 22,
            username: "project-viewer",
            password_hash: "secret123",
            role_id: 2,
            role_name: "user",
          },
        ],
      };
    }
    if (sql.includes("UPDATE users SET password_hash=$1")) {
      return { rowCount: 1, rows: [] };
    }
    if (sql.includes("SELECT 1") && sql.includes("FROM projects p")) {
      return params[2] === true
        ? { rowCount: 0, rows: [] }
        : { rowCount: 1, rows: [{ "?column?": 1 }] };
    }
    if (sql.includes("SELECT p.*, owner.username AS owner_name")) {
      return {
        rowCount: 1,
        rows: [
          {
            id: 31,
            user_id: 10,
            name: "Shared project",
            description: "Read only",
            status: "active",
            owner_name: "owner",
            owner_role_name: "user",
            created_at: new Date().toISOString(),
            updated_at: new Date().toISOString(),
          },
        ],
      };
    }
    if (sql.includes("SELECT c.*, d.domain_url")) {
      return {
        rowCount: 1,
        rows: [
          {
            id: 501,
            project_id: 31,
            domain_id: 8,
            domain_url: "project.example",
            name: "Visible campaign",
            target_url: "https://target.example/landing",
            param_key: "q",
            param_value: "visible",
            stats_redirects: 12,
            is_active: true,
          },
        ],
      };
    }
    if (sql.includes("SELECT domain_id, project_id") && sql.includes("FROM campaigns")) {
      return {
        rowCount: 1,
        rows: [{ domain_id: 8, project_id: 31 }],
      };
    }
    if (sql.includes("AS domain_access") && sql.includes("AS project_access")) {
      return {
        rowCount: 1,
        rows: [{ domain_access: false, project_access: true }],
      };
    }
    if (sql.includes("SELECT domain_id AS domain_id") && sql.includes("FROM campaigns")) {
      return { rowCount: 1, rows: [{ domain_id: 8 }] };
    }
    if (sql.includes("FROM domain_user_access") && sql.includes("WHERE domain_id=$1 AND user_id=$2")) {
      return { rowCount: 0, rows: [] };
    }
    if (sql.includes("SELECT s.*, d.domain_url")) {
      return { rowCount: 0, rows: [] };
    }
    if (sql.includes("FROM project_user_access pua") && sql.includes("JOIN users u")) {
      return {
        rowCount: 1,
        rows: [
          {
            id: 22,
            username: "project-viewer",
            access_level: "viewer",
          },
        ],
      };
    }
    if (sql.includes("INSERT INTO admin_audit_logs")) {
      return { rowCount: 1, rows: [] };
    }
    throw new Error(`Unhandled query in project viewer test: ${sql}`);
  };

  const agent = request.agent(adminApp);
  const loginPage = await agent.get("/login");
  const loginCsrf = extractCsrf(loginPage.text);
  await agent
    .post("/login")
    .type("form")
    .send({
      username: "project-viewer",
      password: "secret123",
      _csrf: loginCsrf,
    });

  const projectPage = await agent.get("/projects/31");
  assert.equal(projectPage.status, 200);
  assert.match(projectPage.text, /Visible campaign/);
  assert.match(projectPage.text, /báo cáo và log/);
  assert.match(projectPage.text, /Không chỉnh sửa/);
  assert.match(projectPage.text, /campaigns\/501\/report/);
  assert.match(projectPage.text, /campaigns\/501\/logs/);
  assert.doesNotMatch(projectPage.text, /projects\/31\/links\/assign/);
  assert.doesNotMatch(projectPage.text, /campaigns\/edit\/501/);

  const report = await agent.get("/campaigns/501/report");
  assert.equal(report.status, 302);
  assert.equal(report.headers.location, "/campaigns/501/report/v2");

  const edit = await agent.get("/campaigns/edit/501");
  assert.equal(edit.status, 403);

  const csrf = extractCsrf(projectPage.text);
  const forbidden = await agent
    .post("/projects/31/links/assign")
    .type("form")
    .send({ link_ref: "campaign:501", _csrf: csrf });
  assert.equal(forbidden.status, 403);
});

test("regular users own unlimited domains, private Telegram settings, and no user administration", async () => {
  const insertedDomains = [];
  let telegramSettingsUserId = null;

  db.query = async (sql, params = []) => {
    if (sql.includes("SELECT u.*, r.name as role_name FROM users")) {
      return {
        rowCount: 1,
        rows: [
          {
            id: 77,
            username: "member",
            password_hash: "secret123",
            role_id: 2,
            role_name: "user",
          },
        ],
      };
    }
    if (sql.includes("UPDATE users SET password_hash=$1")) {
      return { rowCount: 1, rows: [] };
    }
    if (sql.includes("INSERT INTO domains (domain_url, safe_template")) {
      insertedDomains.push(params);
      return { rowCount: 1, rows: [{ id: 100 + insertedDomains.length }] };
    }
    if (sql.includes("telegram_chat_id, telegram_username")) {
      telegramSettingsUserId = params[0];
      return {
        rowCount: 1,
        rows: [
          {
            telegram_chat_id: null,
            telegram_link_alerts: true,
            telegram_system_alerts: false,
          },
        ],
      };
    }
    if (sql.includes("SELECT id AS domain_id") && sql.includes("FROM domains")) {
      return { rowCount: 1, rows: [{ domain_id: 999 }] };
    }
    if (sql.includes("FROM domain_user_access") && sql.includes("WHERE domain_id=$1 AND user_id=$2")) {
      return { rowCount: 0, rows: [] };
    }
    if (sql.includes("INSERT INTO admin_audit_logs")) {
      return { rowCount: 1, rows: [] };
    }
    throw new Error(`Unhandled query in user isolation test: ${sql}`);
  };

  const agent = request.agent(adminApp);
  const loginPage = await agent.get("/login");
  const loginCsrf = extractCsrf(loginPage.text);
  const loginRes = await agent
    .post("/login")
    .type("form")
    .send({ username: "member", password: "secret123", _csrf: loginCsrf });
  assert.equal(loginRes.status, 302);

  const welcome = await agent.get("/");
  const formCsrf = extractCsrf(welcome.text);
  for (const domain of ["first.example", "second.example"]) {
    const createRes = await agent
      .post("/domains/create")
      .type("form")
      .send({
        domain_url: domain,
        safe_template: "clean",
        _csrf: formCsrf,
      });
    assert.equal(createRes.status, 302);
  }

  assert.equal(insertedDomains.length, 2);
  assert.deepEqual(
    insertedDomains.map((params) => [params[0], params[2], params[3]]),
    [
      ["first.example", 77, 77],
      ["second.example", 77, 77],
    ]
  );

  const telegramPage = await agent.get("/account/telegram");
  assert.equal(telegramPage.status, 200);
  assert.equal(telegramSettingsUserId, 77);
  assert.doesNotMatch(telegramPage.text, /name="telegram_system_alerts"/);

  const otherDomain = await agent.get("/domains/999");
  assert.equal(otherDomain.status, 403);

  const userAdmin = await agent.get("/users");
  assert.equal(userAdmin.status, 403);
});
