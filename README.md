# HomeSIEM v2
Lightweight SIEM for a home router (Raspberry Pi 3B). Python 3.7+ standard library only, ~30 MB RAM.

Features: UDP+TCP syslog collection, normalization, JSON rule engine (threshold / distinct / sequence / new-asset / IOC),
MITRE tags, alert dedup + ack/close workflow, asset discovery, event search (`src:1.2.3.4 cat:auth act:fail text`),
24h chart, CSV export, ntfy/Telegram/webhook alerts, retention purge, batched SQLite writes (SD-card friendly).

## Install
    sudo apt install -y python3
    sudo useradd -r -s /usr/sbin/nologin homesiem
    sudo mkdir -p /opt/homesiem/data && sudo cp homesiem.py web.py rules.json iocs.txt config.json /opt/homesiem/
    sudo chown -R homesiem /opt/homesiem/data
    sudoedit /opt/homesiem/config.json      # set web_password, allowed_sources (router IP), ntfy_url ...
    sudo cp homesiem.service /etc/systemd/system/ && sudo systemctl enable --now homesiem
    python3 selftest.py                      # optional: verifies everything end to end

Dashboard: http://PI_IP:8080 (login from config.json). Syslog port: 5514 (UDP and TCP).

## Router (OpenWrt)
    uci set system.@system[0].log_ip='PI_IP'; uci set system.@system[0].log_port='5514'
    uci set system.@system[0].log_proto='udp'
    uci set dhcp.@dnsmasq[0].logqueries='1'
    uci set firewall.@zone[1].log='1'        # WAN zone: log rejected/dropped packets
    uci commit && /etc/init.d/log restart && /etc/init.d/dnsmasq restart

Other firmware: use its "remote syslog" setting; parsers live in `parse()` in homesiem.py.

## Config keys (config.json)
web_user, web_password, web_port, allowed_sources (list of router IPs), retention_days, learning_minutes (silent
device learning on first run), alert_cooldown, notify_levels, store_cats (add "dns" to store DNS queries),
ntfy_url, telegram_token/telegram_chat, webhook_url.

Rules: edit rules.json (set "enabled": false to disable). IOCs: add IPs/domains to iocs.txt. Restart after edits.
The dashboard is plain HTTP with basic auth: keep it on your LAN.
