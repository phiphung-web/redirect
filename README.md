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

## Notes

- Safe page templates live in `src/views/safepages`.
- The new clean template is `clean`.
- Admin views use shared styling from `public/css/app.css`.
