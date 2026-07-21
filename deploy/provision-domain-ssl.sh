#!/usr/bin/env bash
set -euo pipefail

if [[ "${EUID}" -ne 0 ]]; then
  echo "SSL provisioner must run as root" >&2
  exit 1
fi

mode="provision"
if [[ "${1:-}" == "--remove" ]]; then
  mode="remove"
  shift
fi

domain="${1:-}"
if [[ ! "${domain}" =~ ^([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$ ]]; then
  echo "Invalid domain name" >&2
  exit 2
fi

site_name="redirect-domain-${domain}"
site_available="/etc/nginx/sites-available/${site_name}"
site_enabled="/etc/nginx/sites-enabled/${site_name}"

if [[ "${mode}" == "remove" ]]; then
  rm -f "${site_enabled}" "${site_available}"
  nginx -t
  systemctl reload nginx
  if command -v certbot >/dev/null 2>&1; then
    certbot delete --cert-name "${domain}" --non-interactive >/dev/null 2>&1 || true
  fi
  printf '{"domain":"%s","removed":true}\n' "${domain}"
  exit 0
fi

if [[ "${LETSENCRYPT_AGREE_TOS:-false}" != "true" ]]; then
  echo "LETSENCRYPT_AGREE_TOS=true is required before certificate issuance" >&2
  exit 3
fi
if [[ ! "${CERTBOT_EMAIL:-}" =~ ^[^[:space:]@]+@[^[:space:]@]+\.[^[:space:]@]+$ ]]; then
  echo "CERTBOT_EMAIL must contain a valid operational email address" >&2
  exit 4
fi
if ! command -v certbot >/dev/null 2>&1; then
  echo "certbot is not installed" >&2
  exit 5
fi

webroot="${SSL_ACME_WEBROOT:-/var/www/redirect-pro-acme}"
install -d -m 0755 "${webroot}/.well-known/acme-challenge"

certbot certonly \
  --webroot \
  --webroot-path "${webroot}" \
  --domain "${domain}" \
  --cert-name "${domain}" \
  --email "${CERTBOT_EMAIL}" \
  --agree-tos \
  --non-interactive \
  --keep-until-expiring

certificate="/etc/letsencrypt/live/${domain}/fullchain.pem"
private_key="/etc/letsencrypt/live/${domain}/privkey.pem"
if [[ ! -s "${certificate}" || ! -s "${private_key}" ]]; then
  echo "Certbot completed without the expected certificate files" >&2
  exit 6
fi

tmp_site="$(mktemp)"
backup_site=""
cleanup() { rm -f "${tmp_site}"; }
trap cleanup EXIT

if [[ -f "${site_available}" ]]; then
  backup_site="${site_available}.bak.$(date +%s)"
  cp -a "${site_available}" "${backup_site}"
fi

cat >"${tmp_site}" <<EOF
server {
    listen 80;
    server_name ${domain};

    location ^~ /.well-known/acme-challenge/ {
        root ${webroot};
        default_type text/plain;
        try_files \$uri =404;
    }

    location / {
        proxy_pass http://127.0.0.1:4101;
        proxy_http_version 1.1;
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;
        proxy_connect_timeout 3s;
        proxy_read_timeout 10s;
    }
}

server {
    listen 443 ssl;
    server_name ${domain};

    ssl_certificate ${certificate};
    ssl_certificate_key ${private_key};
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_session_cache shared:RedirectTLS:10m;
    ssl_session_timeout 1d;

    location / {
        proxy_pass http://127.0.0.1:4101;
        proxy_http_version 1.1;
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto https;
        proxy_connect_timeout 3s;
        proxy_read_timeout 10s;
    }
}
EOF

install -m 0644 "${tmp_site}" "${site_available}"
ln -sfn "${site_available}" "${site_enabled}"
if ! nginx -t; then
  rm -f "${site_enabled}"
  if [[ -n "${backup_site}" ]]; then
    cp -a "${backup_site}" "${site_available}"
    ln -sfn "${site_available}" "${site_enabled}"
  else
    rm -f "${site_available}"
  fi
  nginx -t
  exit 7
fi
systemctl reload nginx

expiry_raw="$(openssl x509 -enddate -noout -in "${certificate}" | cut -d= -f2-)"
expiry_iso="$(date -u -d "${expiry_raw}" +%Y-%m-%dT%H:%M:%SZ)"
printf '{"domain":"%s","expires_at":"%s"}\n' "${domain}" "${expiry_iso}"
