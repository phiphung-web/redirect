require("dotenv").config({ quiet: true });
const express = require("express");
const path = require("path");
const geoip = require("geoip-lite");
const UAParser = require("ua-parser-js");
const db = require("./config/db");
const { logTraffic } = require("./services/logger");

const app = express();
const PORT = process.env.PORT || 4001;

app.set("view engine", "ejs");
app.set("views", path.join(__dirname, "views")); // Cùng cấp src

app.get(/.*/, async (req, res) => {
  let campaign = null,
    domain = null;
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
    const requestUrl = `${req.protocol}://${host}${req.originalUrl}`;

    // 1. Lấy Domain & Config
    const rDom = await db.query(
      `SELECT * FROM domains WHERE domain_url = $1 AND status = 'active'`,
      [host]
    );

    // Render Safe Page Function
    const renderSafe = (domData, action = "safe_page", detail) => {
      if (!domData) return res.status(404).send("Domain not configured");

      const tpl = domData.safe_template || "news";
      const cfg = domData.safe_content || {};

      logTraffic({
        domainId: domData.id,
        campaignId: campaign ? campaign.id : null,
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
        },
        (err, html) => {
          if (err) return res.send(`<h1>${host}</h1>`);
          res.send(html);
        }
      );
    };

    if (!rDom.rowCount) return res.status(404).send("Domain Error");
    domain = rDom.rows[0];

    // 2. Tìm Campaign (Theo params)
    for (const [key, val] of Object.entries(queryParams)) {
      const rCamp = await db.query(
        `SELECT * FROM campaigns WHERE domain_id=$1 AND param_key=$2 AND param_value=$3 LIMIT 1`,
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
    if (domain) return renderSafe(domain, "error");
    res.status(500).send("Server Error");
  }
});

app.listen(PORT, () => console.log(`Engine V2 running on ${PORT}`));
