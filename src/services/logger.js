const db = require("../config/db");
const { performance } = require("../config/app");

const queue = [];
let flushing = false;
let dropped = 0;

const normalizeTraffic = (data) => {
  const refParts = [];
  if (data.referer) refParts.push(`ref=${data.referer}`);
  if (data.requestUrl) refParts.push(`url=${data.requestUrl}`);
  if (data.detail) refParts.push(`detail=${data.detail}`);
  return [
    data.campaignId || null,
    data.domainId,
    data.ip,
    data.country,
    data.city,
    data.device,
    data.os,
    data.browser,
    data.action,
    refParts.length ? refParts.join(" | ") : null,
    data.ua,
    data.requestId || null,
    data.shortLinkId || null,
  ];
};

const insertRows = async (rows, columnCount = 13) => {
  const columns = [
    "campaign_id",
    "domain_id",
    "ip",
    "country",
    "city",
    "device_type",
    "os_name",
    "browser_name",
    "action",
    "referer",
    "user_agent",
    "request_id",
    "short_link_id",
  ].slice(0, columnCount);
  const params = [];
  const tuples = rows.map((row, rowIndex) => {
    const selected = row.slice(0, columnCount);
    selected.forEach((value) => params.push(value));
    return `(${selected
      .map((_, columnIndex) => `$${rowIndex * columnCount + columnIndex + 1}`)
      .join(", ")})`;
  });
  await db.query(
    `INSERT INTO traffic_logs (${columns.join(", ")}) VALUES ${tuples.join(", ")}`,
    params
  );
};

const persistRows = async (rows) => {
  try {
    await insertRows(rows, 13);
  } catch (error) {
    if (error.code !== "42703") throw error;
    try {
      await insertRows(rows, 12);
    } catch (requestIdError) {
      if (requestIdError.code !== "42703") throw requestIdError;
      await insertRows(rows, 11);
    }
  }
};

const flushTrafficLogs = async () => {
  if (flushing || !queue.length) return;
  flushing = true;
  const rows = queue.splice(0, performance.trafficBatchSize);
  try {
    await persistRows(rows);
  } catch (error) {
    const available = Math.max(0, performance.trafficQueueMax - queue.length);
    queue.unshift(...rows.slice(0, available));
    console.error("Traffic batch failed:", error.message);
  } finally {
    flushing = false;
    if (queue.length >= performance.trafficBatchSize) {
      setImmediate(flushTrafficLogs);
    }
  }
};

const logTraffic = (data) => {
  const row = normalizeTraffic(data);
  if (!performance.trafficBufferEnabled) {
    return persistRows([row]).catch((error) =>
      console.error("Traffic log failed:", error.message)
    );
  }
  if (queue.length >= performance.trafficQueueMax) {
    dropped += 1;
    return;
  }
  queue.push(row);
  if (queue.length >= performance.trafficBatchSize) {
    setImmediate(flushTrafficLogs);
  }
};

if (performance.trafficBufferEnabled) {
  const timer = setInterval(flushTrafficLogs, performance.trafficFlushMs);
  timer.unref();
}

module.exports = {
  logTraffic,
  flushTrafficLogs,
  getTrafficBufferStats: () => ({
    queued: queue.length,
    dropped,
    flushing,
  }),
};
