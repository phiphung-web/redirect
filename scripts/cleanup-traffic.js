require("dotenv").config({ quiet: true });

const db = require("../src/config/db");

const retentionDays = Number.parseInt(process.env.LOG_RETENTION_DAYS || "30", 10);
const auditRetentionDays = Number.parseInt(
  process.env.AUDIT_RETENTION_DAYS || "7",
  10
);

const run = async () => {
  if (!Number.isInteger(retentionDays) || retentionDays < 1) {
    throw new Error("LOG_RETENTION_DAYS must be a positive integer");
  }
  if (!Number.isInteger(auditRetentionDays) || auditRetentionDays < 1) {
    throw new Error("AUDIT_RETENTION_DAYS must be a positive integer");
  }
  const client = await db.connect();
  try {
    await client.query("BEGIN");
    await client.query(
      `INSERT INTO traffic_daily_stats
         (day, domain_id, campaign_id, action, hits, updated_at)
       SELECT created_at::date, COALESCE(domain_id, 0), COALESCE(campaign_id, 0), action, COUNT(*), now()
       FROM traffic_logs
       WHERE created_at < now() - ($1::text || ' days')::interval
       GROUP BY created_at::date, domain_id, campaign_id, action
       ON CONFLICT (day, domain_id, campaign_id, action)
       DO UPDATE SET
         hits = traffic_daily_stats.hits + EXCLUDED.hits,
         updated_at = now()`,
      [retentionDays]
    );
    const result = await client.query(
      `DELETE FROM traffic_logs
       WHERE created_at < now() - ($1::text || ' days')::interval`,
      [retentionDays]
    );
    const auditResult = await client.query(
      `DELETE FROM admin_audit_logs
       WHERE created_at < now() - ($1::text || ' days')::interval`,
      [auditRetentionDays]
    );
    await client.query("COMMIT");
    console.log(`Traffic cleanup completed: ${result.rowCount} rows archived`);
    console.log(
      `Admin audit cleanup completed: ${auditResult.rowCount} rows removed`
    );
  } catch (error) {
    await client.query("ROLLBACK");
    throw error;
  } finally {
    client.release();
  }
};

run()
  .catch((error) => {
    console.error("Traffic cleanup failed:", error.message);
    process.exitCode = 1;
  })
  .finally(() => db.end());
