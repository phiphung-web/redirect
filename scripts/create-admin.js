require("dotenv").config({ quiet: true });

const db = require("../src/config/db");
const { hashPassword } = require("../src/services/passwords");

const username = String(process.env.ADMIN_USERNAME || "").trim();
const password = String(process.env.ADMIN_PASSWORD || "");

const run = async () => {
  if (!username || username.length < 3) {
    throw new Error("Set ADMIN_USERNAME with at least 3 characters");
  }
  if (password.length < 12) {
    throw new Error("Set ADMIN_PASSWORD with at least 12 characters");
  }

  const client = await db.connect();
  try {
    await client.query("BEGIN");
    const role = await client.query(
      `INSERT INTO roles (name, description)
       VALUES ('super_admin', 'Full system access')
       ON CONFLICT (name) DO UPDATE SET description=EXCLUDED.description
       RETURNING id`
    );
    const passwordHash = await hashPassword(password);
    await client.query(
      `INSERT INTO users (username, password_hash, role_id)
       VALUES ($1, $2, $3)
       ON CONFLICT (username)
       DO UPDATE SET password_hash=EXCLUDED.password_hash, role_id=EXCLUDED.role_id`,
      [username, passwordHash, role.rows[0].id]
    );
    await client.query("COMMIT");
    console.log(`Super admin is ready: ${username}`);
  } catch (error) {
    await client.query("ROLLBACK");
    throw error;
  } finally {
    client.release();
  }
};

run()
  .catch((error) => {
    console.error("Create admin failed:", error.message);
    process.exitCode = 1;
  })
  .finally(() => db.end());
