# Vultr deployment

Cheapest supported starting plan: Cloud Compute with 1 vCPU, 1 GB RAM and Ubuntu 24.04 LTS for low initial traffic. Add 1 GB swap and use `deploy/postgresql-1gb.conf.example`. A 2 GB plan remains the recommended production baseline once traffic becomes regular.

## 1. System packages

```bash
sudo apt update
sudo apt install -y nginx postgresql postgresql-client git curl certbot python3-certbot-nginx
curl -fsSL https://deb.nodesource.com/setup_20.x | sudo -E bash -
sudo apt install -y nodejs
sudo npm install -g pm2
```

## 2. Database

```bash
sudo -u postgres psql
CREATE USER redirect_pro WITH PASSWORD 'replace-with-a-long-password';
CREATE DATABASE redirect_pro OWNER redirect_pro;
\q

psql -h 127.0.0.1 -U redirect_pro -d redirect_pro -f database/schema_backup.sql
cp .env.production.example .env
# Edit .env before continuing.
npm ci --omit=dev
npm run migrate
```

Create the first account without putting the password in shell history permanently:

```bash
read -p "Admin username: " ADMIN_USERNAME
read -s -p "Admin password: " ADMIN_PASSWORD
export ADMIN_USERNAME ADMIN_PASSWORD
npm run create:admin
unset ADMIN_USERNAME ADMIN_PASSWORD
```

## 3. Services

```bash
pm2 start ecosystem.config.cjs
pm2 save
pm2 startup
```

Copy `deploy/nginx.conf.example` to `/etc/nginx/sites-available/linkpilot`, replace `admin.example.com`, enable the site, test Nginx, and request SSL:

```bash
sudo ln -s /etc/nginx/sites-available/linkpilot /etc/nginx/sites-enabled/linkpilot
sudo nginx -t
sudo systemctl reload nginx
sudo certbot --nginx -d admin.example.com
```

Every redirect domain should point its DNS A record to the Vultr public IPv4. The admin hostname should be reserved for the admin service and should not be used as a campaign domain.

## 4. Maintenance

Install the jobs from `deploy/crontab.example`. Verify backups regularly with `pg_restore --list` and perform a real restore test before launch.

Safe update order:

```bash
git pull
npm ci --omit=dev
npm run migrate
npm test
pm2 reload linkpilot-ads
pm2 reload linkpilot-admin
pm2 logs --lines 100
```

## 5. Scaling triggers

Upgrade the VPS when one of these remains true during normal traffic:

- memory usage stays above 80%;
- swap is used continuously;
- PostgreSQL connections remain near `DB_POOL_MAX`;
- p95 redirect latency exceeds 300 ms;
- the traffic queue grows instead of returning to zero.

Move to 2 vCPU / 4 GB before adding Redis or separating PostgreSQL. Vertical scaling is the simplest and safest first upgrade for this product.
