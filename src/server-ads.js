require("dotenv").config({ quiet: true });
const express = require("express");
const helmet = require("helmet");
const path = require("path");
const geoip = require("geoip-lite");
const UAParser = require("ua-parser-js");
const { ports, trustProxy } = require("./config/app");
const db = require("./config/db");
const { requestContext } = require("./middleware/request-context");
const { logTraffic } = require("./services/logger");
const {
  normalizeSafeTemplate,
  normalizeShortCode,
  sanitizeCustomCss,
  sanitizeCustomHtml,
} = require("./utils/validation");

const app = express();
const PORT = ports.ads;

app.set("trust proxy", trustProxy);
app.use(helmet({ contentSecurityPolicy: false }));
app.use(requestContext);

app.set("view engine", "ejs");
app.set("views", path.join(__dirname, "views")); // Cùng cấp src

app.get(/.*/, async (req, res) => {
  let campaign = null,
    domain = null;
  let renderSafe = null;
  const host = req.get("host");
  const rawIp =
    req.headers["cf-connecting-ip"] ||
    req.headers["x-forwarded-for"] ||
    req.socket.remoteAddress;
  const ip = rawIp ? rawIp.split(",")[0].trim() : "Unknown"; // Lấy IP đầu tiên

  const uaString = req.headers["user-agent"] || "Unknown";
  const queryParams = req.query;

  try {
    const parser = new UAParser(uaString);
    const ua = parser.getResult();
    const deviceType = ua.device?.type || "pc";
    const osName = ua.os?.name || "Unknown";
    const browserName = ua.browser?.name || "Unknown";
    const geo = geoip.lookup(ip);
    const country = geo ? geo.country : "VN";
    const proto = req.get("x-forwarded-proto") || req.protocol || "http";
    const requestUrl = `${proto}://${host}${req.originalUrl}`;

    // 1. Lấy Domain & Config
    const rDom = await db.query(
      `SELECT * FROM domains WHERE domain_url = $1 AND status = 'active'`,
      [host]
    );

    // Render Safe Page Function
    renderSafe = (domData, action = "safe_page", detail) => {
      if (!domData) return res.status(404).send("Domain not configured");

      const tpl = normalizeSafeTemplate(
        campaign?.safe_page_template || domData.safe_template || "news"
      );
      const cfg = campaign?.safe_page_content || domData.safe_content || {};
      const customHtml = sanitizeCustomHtml(cfg.custom_html);
      const customCss = sanitizeCustomCss(cfg.custom_css);

      // Ensure safe pages always render fresh template/content (avoid browser/CDN cache)
      res.set({
        "Cache-Control":
          "no-store, no-cache, must-revalidate, proxy-revalidate, max-age=0",
        Pragma: "no-cache",
        Expires: "0",
        "Surrogate-Control": "no-store",
      });

      logTraffic({
        domainId: domData.id,
        campaignId: campaign ? campaign.id : null,
        requestId: req.requestId,
        ip,
        country,
        city: geo?.city,
        device: deviceType,
        os: osName,
        browser: browserName,
        action,
        referer: req.headers["referer"],
        requestUrl,
        detail,
        ua: uaString,
      });

      res.render(
        `safepages/${tpl}`,
        {
          title: cfg.title || "Tin Tức",
          headline: cfg.headline || "News",
          themeColor: "#333",
          domain: host,
          logo: cfg.logo,
          customHtml,
          customCss,
        },
        (err, html) => {
          if (err) {
            if (tpl === "news") return res.send(`<h1>${host}</h1>`);
            return res.render(
              "safepages/news",
              {
                title: cfg.title || "Tin tức",
                headline: cfg.headline || "News",
                themeColor: "#333",
                domain: host,
                logo: cfg.logo,
                customHtml,
                customCss,
              },
              (fallbackErr, fallbackHtml) => {
                if (fallbackErr) return res.send(`<h1>${host}</h1>`);
                res.send(fallbackHtml);
              }
            );
          }
          res.send(html);
        }
      );
    };

    if (!rDom.rowCount) return res.status(404).send("Domain Error");
    domain = rDom.rows[0];

    const shortMatch = req.path.match(/^\/s\/([^/?#]+)\/?$/);
    if (shortMatch) {
      let shortCode;
      try {
        shortCode = normalizeShortCode(decodeURIComponent(shortMatch[1]));
      } catch (e) {
        return renderSafe(domain, "safe_page_short_invalid", "short_invalid");
      }

      const rShort = await db.query(
        `
          SELECT * FROM short_links
          WHERE domain_id=$1 AND lower(code)=lower($2)
          LIMIT 1
        `,
        [domain.id, shortCode]
      );
      const shortLink = rShort.rows[0];
      if (!shortLink || !shortLink.is_active) {
        return renderSafe(domain, "safe_page_short_inactive", "short_link_inactive");
      }

      db.query(`UPDATE short_links SET clicks = clicks + 1 WHERE id=$1`, [
        shortLink.id,
      ]).catch((e) => console.error("Short Link Click Error:", e.message));
      logTraffic({
        domainId: domain.id,
        campaignId: null,
        shortLinkId: shortLink.id,
        requestId: req.requestId,
        ip,
        country,
        city: geo?.city,
        action: "short_redirect",
        referer: req.headers["referer"],
        requestUrl,
        detail: `short=${shortLink.id}`,
        device: deviceType,
        os: osName,
        browser: browserName,
        ua: uaString,
      });

      const targetObj = new URL(shortLink.target_url);
      for (const [k, v] of Object.entries(queryParams)) {
        if (!targetObj.searchParams.has(k)) targetObj.searchParams.append(k, v);
      }

      return res.redirect(302, targetObj.toString());
    }

    // 2. Tìm Campaign (Theo params)
    for (const [key, val] of Object.entries(queryParams)) {
      const rCamp = await db.query(
        `
          SELECT c.*, sp.template AS safe_page_template, sp.content AS safe_page_content
          FROM campaigns c
          LEFT JOIN safe_pages sp ON sp.id = c.safe_page_id AND sp.is_active
          WHERE c.domain_id=$1 AND c.param_key=$2 AND c.param_value=$3
          LIMIT 1
        `,
        [domain.id, key, val]
      );
      if (rCamp.rowCount) {
        campaign = rCamp.rows[0];
        break;
      }
    }

    // 3. Check Điều Kiện
    if (!campaign || !campaign.is_active)
      return renderSafe(domain, "safe_page_inactive", "campaign_inactive");

    // Check Quốc Gia
    const filters = campaign.filters || {};
    if (filters.countries?.length > 0 && !filters.countries.includes(country)) {
      return renderSafe(domain, "safe_page_wrong_country", `country=${country}`);
    }

    // Check Rules (Tham số)
    const rules = campaign.rules || [];
    for (const rule of rules) {
      const val = queryParams[rule.key];
      if (rule.operator === "exists" && (val === undefined || val === ""))
        return renderSafe(
          domain,
          "safe_page_missing_param",
          `missing:${rule.key}`
        );
      if (
        rule.operator === "equals" &&
        (!val || val.toLowerCase() !== rule.value.toLowerCase())
      )
        return renderSafe(
          domain,
          "safe_page_wrong_param_val",
          `expect ${rule.key}=${rule.value}; got=${val || "null"}`
        );
    }

    // 4. Redirect
    const targetObj = new URL(campaign.target_url);
    for (const [k, v] of Object.entries(queryParams)) {
      if (!targetObj.searchParams.has(k)) targetObj.searchParams.append(k, v);
    }

    db.query(
      `UPDATE campaigns SET stats_redirects = stats_redirects + 1 WHERE id=$1`,
      [campaign.id]
    );
    logTraffic({
      domainId: domain.id,
      campaignId: campaign.id,
      requestId: req.requestId,
      ip,
      country,
      action: "redirect",
      referer: req.headers["referer"],
      requestUrl,
      device: deviceType,
      os: osName,
      browser: browserName,
      ua: uaString,
    });

    res.redirect(302, targetObj.toString());
  } catch (e) {
    console.error(e);
    if (domain && renderSafe) return renderSafe(domain, "error");
    res.status(500).send("Server Error");
  }
});

if (require.main === module) {
  app.listen(PORT, () => console.log(`Engine V2 running on ${PORT}`));
}

module.exports = app;
