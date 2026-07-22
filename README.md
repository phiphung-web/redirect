# LinkPilot / Redirect Pro

Production-oriented redirect and campaign management for a single organization. The product keeps the public redirect engine isolated from the admin panel and runs on a standard Ubuntu VPS, including the current Contabo deployment.

## Product modules

- conditional links with parameter, country and device routing;
- automatic redirect links with a configurable 1-30 second wait;
- exactly two built-in fallback layouts: an English repair-services page and an English mobile 18+ age gate;
- one Safe Page is selected when a domain is added and applies to every campaign on that domain;
- opening a configured domain without a valid link identifier displays that domain's Safe Page;
- both link types are created and managed from the domain detail screen;
- campaign and short-link reports;
- users, roles and admin audit logs;
- health endpoints, database backups and raw-log retention.

## Delayed-link reporting

Delayed links keep separate lifecycle metrics:

- `short_link_open`: the Safe Page loaded;
- `short_redirect_confirmed`: the browser stayed until the configured delay and sent a signed, one-time confirmation immediately before navigation;
- an open that remains unconfirmed is reported separately and is not counted as a redirect.

Confirmation totals can be lower when visitors leave before the delay ends, lose connectivity, disable JavaScript or use a browser that blocks the confirmation request. Historical `short_redirect` rows predate this protocol and are displayed as unverified legacy data.

## Meta Ads URL parameters

The conditional-link builder opens with four editable rules: `utm_source`, `utm_medium`, `utm_campaign`, and `utm_content`. Their exact-match values are also used to build the query string shown below the rules.

Paste only the generated string into the ad-level **Tracking → URL parameters** field, without a leading `?`. The system always checks that `fbclid` exists, but keeps that internal rule out of both the form and copied string because Meta supplies it automatically. Never place email addresses, phone numbers or other personal data in UTM values.

Reference: [Meta Business Help — URL parameters](https://www.facebook.com/business/help/1016122818401732).

## Automatic domain SSL

When automatic SSL is enabled, adding a domain creates a background certificate
job. The domain detail screen shows `pending`, `active`, or `error`, records the
certificate expiry date, and provides a manual retry action. Nginx keeps a
fallback TLS listener available while issuance is pending so proxied domains do
not time out on port 443.

Before adding a domain, point its DNS `A` record to the server and make sure
inbound ports 80 and 443 are open. For the most reliable first issuance on
Cloudflare, use DNS-only mode, then enable the proxy and `Full (strict)` after
the domain certificate becomes active. A proxied record can also work when
Cloudflare does not force the HTTP challenge through strict origin TLS.

On Ubuntu, after reviewing and accepting the Let's Encrypt Subscriber
Agreement, set the operational email and enable the feature in `.env`:

```bash
AUTO_SSL_ENABLED=true
CERTBOT_EMAIL=admin@example.com
LETSENCRYPT_AGREE_TOS=true
```

Install the fixed, root-owned provisioning helper once:

```bash
sudo bash deploy/install-auto-ssl.sh
```

The application invokes only `/usr/local/sbin/redirect-pro-provision-domain`
with a validated domain argument. Certbot uses HTTP-01 webroot validation;
certificate renewal is handled by `certbot.timer`, followed by a safe Nginx
configuration test and reload.

## Performance model

The redirect hot path uses short-lived in-process caches for domain, campaign and short-link configuration. Most traffic logs and counters are buffered in production so redirect responses are not blocked by reporting writes. Delayed-link opens are persisted immediately because their row is atomically promoted when the browser confirms navigation.

Default production profile for a 6-vCPU / 12-GB VPS:

- four clustered redirect workers (bounded to at most six);
- one admin process;
- PostgreSQL pool limited to 8 connections per process;
- 30-second routing cache;
- five-minute stale-cache safety window during short database interruptions;
- traffic inserts in batches of 100;
- counter flush every two seconds;
- raw logs retained for 30 days.

See [docs/PERFORMANCE.md](docs/PERFORMANCE.md) for the measured Contabo baseline, tuned result and capacity caveats.

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

See [docs/VULTR_DEPLOY.md](docs/VULTR_DEPLOY.md) for the generic Ubuntu VPS, PostgreSQL, Nginx, SSL, backup and scaling procedure.

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
