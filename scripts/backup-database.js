require("dotenv").config({ quiet: true });

const fs = require("fs");
const path = require("path");
const { spawn } = require("child_process");
const { db } = require("../src/config/app");

const backupDir = path.resolve(process.env.BACKUP_DIR || "./backups");
const retentionDays = Number.parseInt(process.env.BACKUP_RETENTION_DAYS || "14", 10);
const stamp = new Date().toISOString().replace(/[:.]/g, "-");
const output = path.join(backupDir, `${db.database}-${stamp}.dump`);

fs.mkdirSync(backupDir, { recursive: true });

const pgDump = spawn(
  process.env.PG_DUMP_BIN || "pg_dump",
  [
    "--format=custom",
    "--no-owner",
    "--no-privileges",
    "--host",
    db.host,
    "--port",
    String(db.port),
    "--username",
    db.user,
    "--file",
    output,
    db.database,
  ],
  {
    stdio: "inherit",
    env: { ...process.env, PGPASSWORD: db.password },
  }
);

pgDump.on("error", (error) => {
  console.error("Unable to start pg_dump:", error.message);
  process.exitCode = 1;
});

pgDump.on("exit", (code) => {
  if (code !== 0) {
    console.error(`Database backup failed with exit code ${code}`);
    process.exitCode = code || 1;
    return;
  }
  const cutoff = Date.now() - retentionDays * 86400000;
  for (const file of fs.readdirSync(backupDir)) {
    if (!file.endsWith(".dump")) continue;
    const fullPath = path.join(backupDir, file);
    if (fs.statSync(fullPath).mtimeMs < cutoff) fs.unlinkSync(fullPath);
  }
  console.log(`Database backup created: ${output}`);
});
