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

Restore `database/schema_backup.sql`, then apply migrations in `database/migrations` in filename order.

## Upgrade from redirect-check

Before reloading PM2, keep the running process on the old code while preparing files on disk:

```bash
cd ~/redirect
git fetch origin
git diff --name-status HEAD..origin/main
git pull origin main
npm install
```

Apply the new idempotent migrations before the first reload:

```bash
set -a
. ./.env
set +a
export PGPASSWORD="$DB_PASS"
psql -h "$DB_HOST" -p "${DB_PORT:-5432}" -U "$DB_USER" -d "$DB_NAME" -f database/migrations/2026-03-17-admin-audit-log.sql
psql -h "$DB_HOST" -p "${DB_PORT:-5432}" -U "$DB_USER" -d "$DB_NAME" -f database/migrations/2026-03-17-request-id.sql
psql -h "$DB_HOST" -p "${DB_PORT:-5432}" -U "$DB_USER" -d "$DB_NAME" -f database/migrations/2026-04-27-clean-safe-template.sql
```

Then verify and reload:

```bash
npm test
pm2 reload ecosystem.config.cjs
```

The code keeps compatible defaults for the old server when `.env` is missing, but production should still set `DB_*`, `SESSION_SECRET`, `SESSION_NAME`, `ADS_PORT`, and `ADMIN_PORT` explicitly.

## Notes

- Safe page templates live in `src/views/safepages`.
- The new clean template is `clean`.
- Admin views use shared styling from `public/css/app.css`.
