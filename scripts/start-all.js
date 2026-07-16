const { spawn } = require("child_process");

const services = [
  { name: "ads", command: "node", args: ["src/server-ads.js"] },
  { name: "admin", command: "node", args: ["src/server-admin.js"] },
];

const children = services.map((svc) => {
  const child = spawn(svc.command, svc.args, {
    cwd: process.cwd(),
    env: process.env,
    stdio: ["ignore", "pipe", "pipe"],
  });

  child.stdout.on("data", (chunk) => {
    process.stdout.write(`[${svc.name}] ${chunk}`);
  });
  child.stderr.on("data", (chunk) => {
    process.stderr.write(`[${svc.name}] ${chunk}`);
  });
  child.on("exit", (code, signal) => {
    const reason = signal || code;
    process.stderr.write(`[${svc.name}] exited: ${reason}\n`);
    shutdown(code || 1);
  });

  return child;
});

let shuttingDown = false;
const shutdown = (code = 0) => {
  if (shuttingDown) return;
  shuttingDown = true;
  children.forEach((child) => {
    if (!child.killed) child.kill();
  });
  process.exit(code);
};

process.on("SIGINT", () => shutdown(0));
process.on("SIGTERM", () => shutdown(0));
