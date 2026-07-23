#!/usr/bin/env bash
set -euo pipefail

if [[ "${EUID}" -ne 0 ]]; then
  echo "Run this installer as root" >&2
  exit 1
fi

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
install -d -m 0755 /var/www/redirect-pro-acme
install -m 0750 "${script_dir}/provision-domain-ssl.sh" /usr/local/sbin/redirect-pro-provision-domain

apt-get update
DEBIAN_FRONTEND=noninteractive apt-get install -y certbot

install -d -m 0755 /etc/letsencrypt/renewal-hooks/deploy
install -m 0750 "${script_dir}/reload-nginx-after-renew.sh" /etc/letsencrypt/renewal-hooks/deploy/reload-nginx

systemctl enable --now certbot.timer
nginx -t
systemctl reload nginx

echo "Auto SSL helper installed. Configure AUTO_SSL_ENABLED, CERTBOT_EMAIL and LETSENCRYPT_AGREE_TOS in the application environment."
