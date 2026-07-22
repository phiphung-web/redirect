require("dotenv").config({ quiet: true });

const express = require("express");
const helmet = require("helmet");
const path = require("path");
const crypto = require("crypto");
const geoip = require("geoip-lite");
const UAParser = require("ua-parser-js");
const { ports, trustProxy, product, session } = require("./config/app");
const db = require("./config/db");
const { requestContext } = require("./middleware/request-context");
const {
  logTraffic,
  logTrafficNow,
  flushTrafficLogs,
} = require("./services/logger");
const {
  domainCache,
  campaignCache,
  shortLinkCache,
} = require("./services/runtime-cache");
const {
  incrementCampaign,
  incrementShortLink,
  flushCounters,
} = require("./services/counter-buffer");
const {
  normalizeSafeTemplate,
  normalizeShortCode,
} = require("./utils/validation");

const app = express();
const PORT = ports.ads;
const SHORT_CONFIRM_TTL_MS = 10 * 60 * 1000;

app.disable("x-powered-by");
app.set("trust proxy", trustProxy);
app.use(helmet({ contentSecurityPolicy: false }));
app.use(requestContext);
app.set("view engine", "ejs");
app.set("views", path.join(__dirname, "views"));
app.use(
  "/assets",
  express.static(path.join(__dirname, "../public"), {
    immutable: true,
    maxAge: "7d",
  })
);

const signShortRedirect = (payload) => {
  const encoded = Buffer.from(JSON.stringify(payload)).toString("base64url");
  const signature = crypto
    .createHmac("sha256", session.secret)
    .update(encoded)
    .digest("base64url");
  return `${encoded}.${signature}`;
};

const verifyShortRedirect = (token) => {
  const raw = String(token || "");
  const [encoded, signature, extra] = raw.split(".");
  if (!encoded || !signature || extra || raw.length > 2048) return null;
  const expected = crypto
    .createHmac("sha256", session.secret)
    .update(encoded)
    .digest();
  let received;
  try {
    received = Buffer.from(signature, "base64url");
  } catch (_) {
    return null;
  }
  if (received.length !== expected.length || !crypto.timingSafeEqual(received, expected)) {
    return null;
  }
  try {
    const payload = JSON.parse(Buffer.from(encoded, "base64url").toString("utf8"));
    if (
      !payload ||
      !/^[0-9a-f-]{36}$/i.test(String(payload.visitId || "")) ||
      !Number.isInteger(payload.shortLinkId) ||
      !Number.isInteger(payload.domainId) ||
      !Number.isFinite(payload.notBefore) ||
      !Number.isFinite(payload.expiresAt)
    ) {
      return null;
    }
    return payload;
  } catch (_) {
    return null;
  }
};

const normalizeQueryEntries = (query) =>
  Object.entries(query)
    .slice(0, 30)
    .map(([key, value]) => [
      String(key),
      Array.isArray(value) ? String(value[0] || "") : String(value || ""),
    ]);

const getDomain = async (host) => {
  const cacheKey = host.toLowerCase();
  const cached = domainCache.get(cacheKey);
  if (cached !== undefined) return cached;
  try {
    const result = await db.query(
      `SELECT * FROM domains WHERE domain_url = $1 AND status = 'active' LIMIT 1`,
      [cacheKey]
    );
    return domainCache.set(cacheKey, result.rows[0] || null);
  } catch (error) {
    const stale = domainCache.getStale(cacheKey);
    if (stale !== undefined) return stale;
    throw error;
  }
};

const getShortLink = async (domainId, code) => {
  const cacheKey = `${domainId}:${code.toLowerCase()}`;
  const cached = shortLinkCache.get(cacheKey);
  if (cached !== undefined) return cached;
  try {
    const result = await db.query(
      `SELECT * FROM short_links
       WHERE domain_id=$1 AND lower(code)=lower($2)
       LIMIT 1`,
      [domainId, code]
    );
    return shortLinkCache.set(cacheKey, result.rows[0] || null);
  } catch (error) {
    const stale = shortLinkCache.getStale(cacheKey);
    if (stale !== undefined) return stale;
    throw error;
  }
};

const getCampaign = async (domainId, entries) => {
  const missing = [];
  for (const [key, value] of entries) {
    const cacheKey = `${domainId}:${key}:${value}`;
    const cached = campaignCache.get(cacheKey);
    if (cached !== undefined) {
      if (cached) return cached;
    } else {
      missing.push([key, value]);
    }
  }
  if (!missing.length) return null;

  let result;
  try {
    result = await db.query(
      `SELECT c.*
       FROM campaigns c
       JOIN unnest($2::text[], $3::text[]) AS incoming(param_key, param_value)
         ON c.param_key = incoming.param_key AND c.param_value = incoming.param_value
       WHERE c.domain_id=$1
       ORDER BY c.id DESC
       LIMIT 1`,
      [
        domainId,
        missing.map(([key]) => key),
        missing.map(([, value]) => value),
      ]
    );
  } catch (error) {
    for (const [key, value] of entries) {
      const stale = campaignCache.getStale(`${domainId}:${key}:${value}`);
      if (stale) return stale;
    }
    throw error;
  }

  missing.forEach(([key, value]) =>
    campaignCache.set(`${domainId}:${key}:${value}`, null)
  );
  const campaign = result.rows[0] || null;
  if (campaign) {
    campaignCache.set(
      `${domainId}:${campaign.param_key}:${campaign.param_value}`,
      campaign
    );
  }
  return campaign;
};

app.get("/healthz", async (req, res) => {
  try {
    await db.query("SELECT 1");
    return res.json({
      status: "ok",
      service: "redirect-engine",
      product: product.name,
      uptime: Math.round(process.uptime()),
    });
  } catch (error) {
    return res.status(503).json({ status: "error", service: "redirect-engine" });
  }
});

app.post(
  "/s/:code/confirm",
  express.json({ limit: "2kb", type: ["application/json", "text/plain"] }),
  async (req, res) => {
    res.set("Cache-Control", "no-store");
    try {
      const payload = verifyShortRedirect(req.body?.token);
      const now = Date.now();
      if (!payload) return res.status(400).json({ status: "invalid" });
      if (now < payload.notBefore) {
        return res.status(425).json({ status: "too_early" });
      }
      if (now > payload.expiresAt) {
        return res.status(410).json({ status: "expired" });
      }

      const host = String(req.hostname || req.get("host") || "").toLowerCase();
      const domain = await getDomain(host);
      if (!domain || Number(domain.id) !== payload.domainId) {
        return res.status(404).json({ status: "not_found" });
      }

      const code = normalizeShortCode(decodeURIComponent(req.params.code));
      const shortLink = await getShortLink(domain.id, code);
      if (!shortLink?.is_active || Number(shortLink.id) !== payload.shortLinkId) {
        return res.status(404).json({ status: "not_found" });
      }

      const confirmed = await db.query(
        `UPDATE traffic_logs
         SET action='short_redirect_confirmed'
         WHERE request_id=$1
           AND short_link_id=$2
           AND domain_id=$3
           AND action='short_link_open'
         RETURNING id`,
        [payload.visitId, payload.shortLinkId, payload.domainId]
      );
      if (confirmed.rowCount) incrementShortLink(payload.shortLinkId);
      return res.status(204).end();
    } catch (error) {
      console.error(`[${req.requestId}] short redirect confirm error:`, error.message);
      return res.status(500).json({ status: "error" });
    }
  }
);

app.get(/.*/, async (req, res) => {
  let campaign = null;
  let domain = null;
  let renderSafe = null;
  const host = String(req.hostname || req.get("host") || "").toLowerCase();
  const rawIp =
    req.headers["cf-connecting-ip"] ||
    req.headers["x-forwarded-for"] ||
    req.socket.remoteAddress;
  const ip = rawIp ? String(rawIp).split(",")[0].trim() : "Unknown";
  const uaString = req.headers["user-agent"] || "Unknown";
  const queryParams = req.query;
  const queryEntries = normalizeQueryEntries(queryParams);

  try {
    const ua = new UAParser(uaString).getResult();
    const deviceType = ua.device?.type || "desktop";
    const osName = ua.os?.name || "Unknown";
    const browserName = ua.browser?.name || "Unknown";
    const geo = geoip.lookup(ip);
    const country = geo?.country || "XX";
    const proto = req.get("x-forwarded-proto") || req.protocol || "http";
    const requestUrl = `${proto}://${host}${req.originalUrl}`;

    domain = await getDomain(host);

    renderSafe = (domData, action = "safe_page", detail, options = {}) => {
      if (!domData) return res.status(404).send("Domain not configured");
      const tpl = normalizeSafeTemplate(domData.safe_template || "clean");

      res.set({
        "Cache-Control": "no-store, no-cache, must-revalidate, max-age=0",
        Pragma: "no-cache",
        Expires: "0",
      });

      if (!options.skipTrafficLog) {
        logTraffic({
          domainId: domData.id,
          campaignId: campaign?.id || null,
          shortLinkId: options.shortLinkId || null,
          requestId: req.requestId,
          ip,
          country,
          city: geo?.city,
          device: deviceType,
          os: osName,
          browser: browserName,
          action,
          referer: req.headers.referer,
          requestUrl,
          detail,
          ua: uaString,
        });
      }

      const viewData = {
        title: host,
        domain: host,
        ...(options.viewData || {}),
      };

      return res.render(`safepages/${tpl}`, viewData, (error, html) => {
        if (!error) return res.send(html);
        if (tpl === "clean") return res.status(200).send(`<h1>${host}</h1>`);
        return res.render("safepages/clean", viewData, (fallbackError, fallbackHtml) => {
          if (fallbackError) return res.status(200).send(`<h1>${host}</h1>`);
          return res.send(fallbackHtml);
        });
      });
    };

    if (!domain) return res.status(404).send("Domain not configured");

    const shortMatch = req.path.match(/^\/s\/([^/?#]+)\/?$/);
    if (shortMatch) {
      let shortCode;
      try {
        shortCode = normalizeShortCode(decodeURIComponent(shortMatch[1]));
      } catch (error) {
        return renderSafe(domain, "safe_page_short_invalid", "short_invalid");
      }

      const shortLink = await getShortLink(domain.id, shortCode);
      if (!shortLink?.is_active) {
        return renderSafe(
          domain,
          "safe_page_short_inactive",
          "short_link_inactive"
        );
      }

      const target = new URL(shortLink.target_url);
      queryEntries.forEach(([key, value]) => {
        if (!target.searchParams.has(key)) target.searchParams.append(key, value);
      });

      const configuredDelay = Number.parseInt(
        shortLink.redirect_delay_seconds,
        10
      );
      const redirectDelaySeconds = Number.isInteger(configuredDelay)
        ? Math.min(Math.max(configuredDelay, 1), 30)
        : 3;

      const visitId = crypto.randomUUID();
      const notBefore = Date.now() + redirectDelaySeconds * 1000;
      let redirectConfirmToken = null;
      try {
        await logTrafficNow({
          domainId: domain.id,
          shortLinkId: shortLink.id,
          requestId: visitId,
          ip,
          country,
          city: geo?.city,
          device: deviceType,
          os: osName,
          browser: browserName,
          action: "short_link_open",
          referer: req.headers.referer,
          requestUrl,
          detail: `short=${shortLink.id}`,
          ua: uaString,
        });
        redirectConfirmToken = signShortRedirect({
          visitId,
          shortLinkId: Number(shortLink.id),
          domainId: Number(domain.id),
          notBefore,
          expiresAt: notBefore + SHORT_CONFIRM_TTL_MS,
        });
      } catch (error) {
        console.error(`[${req.requestId}] short-link open log error:`, error.message);
      }

      return renderSafe(domain, "short_link_open", `short=${shortLink.id}`, {
        shortLinkId: shortLink.id,
        skipTrafficLog: true,
        viewData: {
          redirectTargetUrl: target.toString(),
          redirectDelaySeconds,
          redirectConfirmUrl: `/s/${encodeURIComponent(shortCode)}/confirm`,
          redirectConfirmToken,
        },
      });
    }

    campaign = await getCampaign(domain.id, queryEntries);
    if (!campaign?.is_active) {
      return renderSafe(domain, "safe_page_inactive", "campaign_inactive");
    }

    const filters = campaign.filters || {};
    if (filters.countries?.length && !filters.countries.includes(country)) {
      return renderSafe(domain, "safe_page_wrong_country", `country=${country}`);
    }
    if (filters.devices?.length && !filters.devices.includes(deviceType)) {
      return renderSafe(domain, "safe_page_wrong_device", `device=${deviceType}`);
    }

    for (const rule of campaign.rules || []) {
      const value = queryParams[rule.key];
      if (rule.operator === "exists" && value === undefined) {
        return renderSafe(domain, "safe_page_missing_param", `missing:${rule.key}`);
      }
      if (
        rule.operator === "equals" &&
        (!value || String(value).toLowerCase() !== String(rule.value).toLowerCase())
      ) {
        return renderSafe(
          domain,
          "safe_page_wrong_param_val",
          `expect ${rule.key}=${rule.value}; got=${value || "null"}`
        );
      }
    }

    const target = new URL(campaign.target_url);
    queryEntries.forEach(([key, value]) => {
      if (!target.searchParams.has(key)) target.searchParams.append(key, value);
    });

    incrementCampaign(campaign.id);
    logTraffic({
      domainId: domain.id,
      campaignId: campaign.id,
      requestId: req.requestId,
      ip,
      country,
      action: "redirect",
      referer: req.headers.referer,
      requestUrl,
      device: deviceType,
      os: osName,
      browser: browserName,
      ua: uaString,
    });
    return res.redirect(302, target.toString());
  } catch (error) {
    console.error(`[${req.requestId}] redirect error:`, error.message);
    if (domain && renderSafe) return renderSafe(domain, "error", error.code);
    return res.status(500).send("Server Error");
  }
});

if (require.main === module) {
  const server = app.listen(PORT, process.env.BIND_HOST || "127.0.0.1", () =>
    console.log(`${product.name} redirect engine listening on ${PORT}`)
  );

  const shutdown = async (signal) => {
    console.log(`${signal} received, flushing redirect buffers...`);
    server.close();
    await Promise.allSettled([flushTrafficLogs(), flushCounters()]);
    await db.end().catch(() => undefined);
    process.exit(0);
  };
  process.once("SIGTERM", () => shutdown("SIGTERM"));
  process.once("SIGINT", () => shutdown("SIGINT"));
}

module.exports = app;
