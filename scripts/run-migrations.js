require("dotenv").config({ quiet: true });

const fs = require("fs");
const path = require("path");
const db = require("../src/config/db");

const migrationsDir = path.join(__dirname, "../database/migrations");

const run = async () => {
  const files = fs
    .readdirSync(migrationsDir)
    .filter((file) => file.endsWith(".sql"))
    .sort();

  if (!files.length) {
    console.log("No migration files found.");
    return;
  }

  console.log(`Running ${files.length} migration file(s) from ${migrationsDir}`);

  for (const file of files) {
    const fullPath = path.join(migrationsDir, file);
    const sql = fs.readFileSync(fullPath, "utf8");
    if (!sql.trim()) {
      console.log(`- ${file}: skipped empty file`);
      continue;
    }

    console.log(`- ${file}: running`);
    await db.query("BEGIN");
    try {
      await db.query(sql);
      await db.query("COMMIT");
      console.log(`- ${file}: ok`);
    } catch (error) {
      await db.query("ROLLBACK");
      error.message = `${file}: ${error.message}`;
      throw error;
    }
  }

  console.log("Migrations completed.");
};

run()
  .catch((error) => {
    console.error("Migration failed:", error.message);
    process.exitCode = 1;
  })
  .finally(() => db.end());
