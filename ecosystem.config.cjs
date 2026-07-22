require("dotenv").config({ quiet: true });

const adsInstances = Math.min(
  Math.max(Number.parseInt(process.env.ADS_INSTANCES || "4", 10) || 4, 1),
  6
);

const apps = [
    {
      name: "linkpilot-ads",
      script: "src/server-ads.js",
      instances: adsInstances,
      exec_mode: "cluster",
      autorestart: true,
      max_memory_restart: process.env.ADS_MAX_MEMORY_RESTART || "700M",
      node_args: "--max-old-space-size=512",
      kill_timeout: 12000,
      listen_timeout: 10000,
      time: true,
      env: {
        NODE_ENV: "production",
      },
    },
    {
      name: "linkpilot-admin",
      script: "src/server-admin.js",
      instances: 1,
      exec_mode: "fork",
      autorestart: true,
      max_memory_restart: "384M",
      node_args: "--max-old-space-size=256",
      kill_timeout: 10000,
      listen_timeout: 10000,
      time: true,
      env: {
        NODE_ENV: "production",
      },
    },
  ];

if (
  ["1", "true", "yes", "on"].includes(
    String(process.env.TELEGRAM_ALERTS_ENABLED || "").toLowerCase()
  )
) {
  apps.push({
    name: "linkpilot-telegram",
    script: "src/services/telegram-bot.js",
    instances: 1,
    exec_mode: "fork",
    autorestart: true,
    max_memory_restart: "192M",
    node_args: "--max-old-space-size=128",
    kill_timeout: 10000,
    time: true,
    env: {
      NODE_ENV: "production",
    },
  });
}

module.exports = { apps };
