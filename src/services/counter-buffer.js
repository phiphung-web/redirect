const db = require("../config/db");
const { performance } = require("../config/app");

const campaignCounters = new Map();
const shortLinkCounters = new Map();
let flushing = false;

const incrementMap = (map, id) => {
  const normalized = Number.parseInt(id, 10);
  if (!Number.isInteger(normalized)) return;
  map.set(normalized, (map.get(normalized) || 0) + 1);
};

const buildValues = (items) => {
  const params = [];
  const tuples = items.map(([id, delta], index) => {
    params.push(id, delta);
    const offset = index * 2;
    return `($${offset + 1}::integer, $${offset + 2}::bigint)`;
  });
  return { params, tuples: tuples.join(", ") };
};

const flushMap = async (map, table, column) => {
  const items = [...map.entries()];
  if (!items.length) return;
  map.clear();
  const { params, tuples } = buildValues(items);
  try {
    await db.query(
      `UPDATE ${table} AS target
       SET ${column} = COALESCE(target.${column}, 0) + delta.value
       FROM (VALUES ${tuples}) AS delta(id, value)
       WHERE target.id = delta.id`,
      params
    );
  } catch (error) {
    items.forEach(([id, delta]) =>
      map.set(id, (map.get(id) || 0) + delta)
    );
    console.error(`Counter flush failed for ${table}:`, error.message);
  }
};

const flushCounters = async () => {
  if (flushing) return;
  flushing = true;
  try {
    await flushMap(campaignCounters, "campaigns", "stats_redirects");
    await flushMap(shortLinkCounters, "short_links", "clicks");
  } finally {
    flushing = false;
  }
};

const incrementCampaign = (id) => {
  if (!performance.counterBufferEnabled) {
    return db
      .query(`UPDATE campaigns SET stats_redirects = stats_redirects + 1 WHERE id=$1`, [id])
      .catch((error) => console.error("Campaign counter error:", error.message));
  }
  incrementMap(campaignCounters, id);
};

const incrementShortLink = (id) => {
  if (!performance.counterBufferEnabled) {
    return db
      .query(`UPDATE short_links SET clicks = clicks + 1 WHERE id=$1`, [id])
      .catch((error) => console.error("Short-link counter error:", error.message));
  }
  incrementMap(shortLinkCounters, id);
};

if (performance.counterBufferEnabled) {
  const timer = setInterval(flushCounters, performance.counterFlushMs);
  timer.unref();
}

module.exports = {
  incrementCampaign,
  incrementShortLink,
  flushCounters,
  getCounterBufferStats: () => ({
    campaignPending: campaignCounters.size,
    shortLinkPending: shortLinkCounters.size,
  }),
};
