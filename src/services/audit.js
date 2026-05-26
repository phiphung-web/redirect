const db = require("../config/db");

const auditAdminAction = async ({
  req,
  action,
  targetType,
  targetId = null,
  status = "success",
  detail = null,
}) => {
  try {
    await db.query(
      `
        INSERT INTO admin_audit_logs
        (request_id, user_id, username, action, target_type, target_id, status, detail, ip, user_agent)
        VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
      `,
      [
        req?.requestId || null,
        req?.session?.user?.id || null,
        req?.session?.user?.username || null,
        action,
        targetType,
        targetId,
        status,
        detail || null,
        req?.ip || null,
        req?.headers?.["user-agent"] || null,
      ]
    );
  } catch (e) {
    console.error("Audit Log Error:", e.message);
  }
};

module.exports = { auditAdminAction };
