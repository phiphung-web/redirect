const db = require("../config/db");

const logTraffic = (data) => {
  const sql = `
        INSERT INTO traffic_logs 
        (campaign_id, domain_id, ip, country, city, device_type, os_name, browser_name, action, referer, user_agent, request_id)
        VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)
    `;
  const legacySql = `
        INSERT INTO traffic_logs 
        (campaign_id, domain_id, ip, country, city, device_type, os_name, browser_name, action, referer, user_agent)
        VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
    `;
  const refParts = [];
  if (data.referer) refParts.push(`ref=${data.referer}`);
  if (data.requestUrl) refParts.push(`url=${data.requestUrl}`);
  if (data.detail) refParts.push(`detail=${data.detail}`);
  const refererVal = refParts.length ? refParts.join(" | ") : null;

  const values = [
    data.campaignId || null,
    data.domainId,
    data.ip,
    data.country,
    data.city,
    data.device,
    data.os,
    data.browser,
    data.action,
    refererVal,
    data.ua,
    data.requestId || null,
  ];
  db.query(sql, values).catch((e) => {
    if (e.code === "42703") {
      return db
        .query(legacySql, values.slice(0, 11))
        .catch((legacyError) => console.error("Log Error:", legacyError.message));
    }
    console.error("Log Error:", e.message);
  });
};

module.exports = { logTraffic };
