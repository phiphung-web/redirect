module.exports = {
  apps: [
    {
      name: "redirect-new-ads",
      script: "src/server-ads.js",
      env: {
        NODE_ENV: "production",
      },
    },
    {
      name: "redirect-new-admin",
      script: "src/server-admin.js",
      env: {
        NODE_ENV: "production",
      },
    },
  ],
};
