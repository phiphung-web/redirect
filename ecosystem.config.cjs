module.exports = {
  apps: [
    {
      name: "linkpilot-ads",
      script: "src/server-ads.js",
      instances: 1,
      exec_mode: "fork",
      autorestart: true,
      max_memory_restart: "260M",
      node_args: "--max-old-space-size=176",
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
      max_memory_restart: "260M",
      node_args: "--max-old-space-size=176",
      kill_timeout: 10000,
      listen_timeout: 10000,
      time: true,
      env: {
        NODE_ENV: "production",
      },
    },
  ],
};
