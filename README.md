# LinkPilot / Redirect Pro

Production-oriented redirect and campaign management for a single organization. The product keeps the public redirect engine isolated from the admin panel and is tuned to start on a small Vultr VPS.

## Product modules

- domain and campaign management;
- parameter, country and device routing;
- reusable fallback page templates;
- short links that preserve tracking parameters;
- campaign and short-link reports;
- users, roles and admin audit logs;
- health endpoints, database backups and raw-log retention.

## Performance model

The redirect hot path uses short-lived in-process caches for domain, campaign and short-link configuration. Traffic logs and counters are buffered in production so redirect responses are not blocked by reporting writes.

Default low-resource profile:

- one redirect process;
- one admin process;
- PostgreSQL pool limited to 6 connections per process;
- 30-second routing cache;
- five-minute stale-cache safety window during short database interruptions;
- traffic inserts in batches of 100;
- counter flush every two seconds;
- raw logs retained for 30 days.

## Local development

```bash
npm install
copy .env.example .env
npm test
npm start
```

Default ports are `4001` for redirect traffic and `4002` for admin.

## Fresh database

Create an empty PostgreSQL database, restore `database/schema_backup.sql`, then run:

```bash
npm run migrate
```

Create the first admin by setting `ADMIN_USERNAME` and `ADMIN_PASSWORD`, then run:

```bash
npm run create:admin
```

## Production

Use `.env.production.example` as the starting point. Production refuses to boot with a missing database password or a session secret shorter than 32 characters.

```bash
npm ci --omit=dev
npm run migrate
npm test
pm2 start ecosystem.config.cjs
```

See [docs/VULTR_DEPLOY.md](docs/VULTR_DEPLOY.md) for the full Vultr, PostgreSQL, Nginx, SSL, backup and scaling procedure.

## Operations

```bash
npm run backup
npm run cleanup:logs
```

Load test only a staging or dedicated test campaign:

```bash
LOAD_TARGET=https://test.example.com/?q=test LOAD_CONCURRENCY=20 LOAD_DURATION_SECONDS=30 npm run test:load
```

Health endpoints:

- redirect engine: `http://127.0.0.1:4101/healthz`
- admin: `http://127.0.0.1:4102/healthz`

## Security and scope

This project is intended for compliant redirect, campaign routing and measurement. It is not designed to present different content to platform reviewers or bypass advertising policies.
