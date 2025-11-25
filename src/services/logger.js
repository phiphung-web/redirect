const db = require("../config/db");

const logTraffic = (data) => {
  const sql = `
        INSERT INTO traffic_logs 
        (campaign_id, domain_id, ip, country, city, device_type, os_name, browser_name, action, referer, user_agent)
        VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
    `;
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
    data.referer,
    data.ua,
  ];
  db.query(sql, values).catch((e) => console.error("Log Error:", e.message));
};

module.exports = { logTraffic };
