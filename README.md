# Redirect Control

Node/Express redirect manager with a separate ads engine and admin panel.

## Local run

```bash
npm install
cp .env.example .env
npm run start:ads
npm run start:admin
```

Default ports:

- Ads engine: `4001`
- Admin panel: `4002`

Run both services in one terminal:

```bash
npm start
```

## Production isolation

Use a separate database, ports, cookie name, and session secret for the new system so it does not collide with the old running system.

```bash
cp .env.production.example .env
npm ci --omit=dev
npm test
npm start
```

Recommended production values:

- `DB_NAME=redirect_v2_new`
- `SESSION_NAME=redirect_new.sid`
- `ADS_PORT` and `ADMIN_PORT` different from the old service
- A long random `SESSION_SECRET`

## PM2

```bash
pm2 start ecosystem.config.cjs
pm2 save
```

Load `.env` from the project directory before starting PM2, or export variables in the shell/service manager.

## Database

Restore `database/schema_backup.sql`, then run all idempotent migrations in filename order:

```bash
npm run migrate
```

The migration runner uses the same `DB_*` settings as the app. Prefer it over
manual `psql -f` commands on production because it avoids `/root/redirect`
permission issues when switching to the `postgres` Linux user.

## Upgrade from redirect-check

Before reloading PM2, keep the running process on the old code while preparing files on disk:

```bash
cd ~/redirect
git fetch origin
git diff --name-status HEAD..origin/main
git pull origin main
npm install
```

Apply migrations before the first reload:

```bash
set -a
. ./.env
set +a
npm run migrate
```

Then verify and reload:

```bash
npm test
pm2 reload ecosystem.config.cjs
```

The code keeps compatible defaults for the old server when `.env` is missing, but production should still set `DB_*`, `SESSION_SECRET`, `SESSION_NAME`, `ADS_PORT`, and `ADMIN_PORT` explicitly.

## Notes

- Safe page templates live in `src/views/safepages`.
- Domain-level safe page settings are the default fallback. Campaigns can use a template from the domain safe-page library instead.
- Short-link detailed reporting requires `traffic_logs.short_link_id`, created by `npm run migrate`.
- Admin views use shared styling from `public/css/app.css`.
