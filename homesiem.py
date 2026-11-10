#!/usr/bin/env python3
"""HomeSIEM v2 - lightweight SIEM for a home router. Python 3.7+, stdlib only.
Collect (syslog UDP/TCP) -> normalize -> correlate (rules.json + IOCs) -> store (SQLite) -> alert -> web UI."""
import ipaddress, json, math, os, queue, re, socket, socketserver, sqlite3, sys, threading, time
import urllib.parse, urllib.request
from collections import defaultdict, deque

BASE = os.path.dirname(os.path.abspath(__file__))
DEFAULTS = {
    "syslog_udp_port": 5514, "syslog_tcp_port": 5514, "allowed_sources": [],
    "web_bind": "0.0.0.0", "web_port": 8080, "web_user": "admin", "web_password": "changeme",
    "db": "data/siem.db", "rules": "rules.json", "iocs": "iocs.txt",
    "retention_days": 14, "learning_minutes": 30, "alert_cooldown": 900,
    "store_cats": ["auth", "fw", "dhcp", "wifi", "other"],
    "notify_levels": ["high", "critical"],
    "ntfy_url": "", "telegram_token": "", "telegram_chat": "", "webhook_url": "",
}
SCHEMA = """
CREATE TABLE IF NOT EXISTS events(id INTEGER PRIMARY KEY, ts REAL, host TEXT, prog TEXT, cat TEXT, act TEXT,
  src TEXT, dst TEXT, sport INT, dport INT, user TEXT, mac TEXT, domain TEXT, msg TEXT);
CREATE INDEX IF NOT EXISTS ev_ts ON events(ts);
CREATE INDEX IF NOT EXISTS ev_src ON events(src);
CREATE TABLE IF NOT EXISTS alerts(id INTEGER PRIMARY KEY, ts REAL, last_seen REAL, rule_id TEXT, title TEXT,
  sev TEXT, grp TEXT, detail TEXT, mitre TEXT, count INT, status TEXT, dedup TEXT);
CREATE INDEX IF NOT EXISTS al_dedup ON alerts(dedup);
CREATE TABLE IF NOT EXISTS assets(mac TEXT PRIMARY KEY, ip TEXT, name TEXT, first_seen REAL, last_seen REAL);
CREATE TABLE IF NOT EXISTS meta(k TEXT PRIMARY KEY, v TEXT);
"""

# ------------------------------------------------------------------ parsing / normalization
HDR = re.compile(r"^<\d+>(?:\w{3}\s+\d+\s[\d:]+\s|\d{4}-\d\d-\d\dT\S+\s)?")
PROG = re.compile(r"(?:^|\s)([\w\-./]+)(?:\[\d+\])?:\s(.*)$", re.S)
IP = re.compile(r"\d{1,3}(?:\.\d{1,3}){3}")
FW, DPT, SPT = re.compile(r"SRC=(\S+) DST=(\S+)"), re.compile(r"DPT=(\d+)"), re.compile(r"SPT=(\d+)")
DNSQ = re.compile(r"query\[(\w+)\] (\S+) from (\S+)")
DHCP = re.compile(r"DHCPACK\([^)]*\) (\S+) ([0-9a-fA-F:]{17})\s*(\S*)")
STA = re.compile(r"AP-STA-CONNECTED ([0-9a-fA-F:]{17})")
USER = re.compile(r"(?:for|user)\s+'?([\w.\-@]+)'?\s+from")
BAD = re.compile(r"Bad password|Failed password|nonexistent user|Invalid user|Login attempt for|failed login", re.I)
GOOD = re.compile(r"Password auth succeeded|Pubkey auth succeeded|Accepted (?:password|publickey)|accepted login", re.I)


def entropy(s):
    return -sum(s.count(c) / len(s) * math.log2(s.count(c) / len(s)) for c in set(s))


def scope(ip):
    try:
        return "public" if ipaddress.ip_address(ip).is_global else "private"
    except ValueError:
        return ""


def parse(line, host, ts):
    line = HDR.sub("", line, 1).strip()
    m = PROG.search(line)
    prog, msg = (m[1], m[2]) if m else ("", line)
    ev = {"ts": ts, "host": host, "prog": prog[:40], "cat": "other", "act": "", "src": "", "dst": "",
          "sport": 0, "dport": 0, "user": "", "mac": "", "domain": "", "dga": 0, "_name": "", "msg": line[:400]}
    if "SRC=" in msg and "DST=" in msg:
        m = FW.search(msg)
        ev.update(cat="fw", act="drop", src=m[1], dst=m[2])
        for k, rx in (("dport", DPT), ("sport", SPT)):
            x = rx.search(msg)
            if x:
                ev[k] = int(x[1])
    elif prog.startswith("dnsmasq"):
        m = DNSQ.search(msg)
        if m:
            d = m[2].lower().rstrip(".")
            label = d.split(".")[0]
            dga = len(label) >= 24 and entropy(label) > 3.8 and not d.endswith((".arpa", ".local"))
            ev.update(cat="dns", act="query", src=m[3], domain=d, dga=int(dga))
        else:
            m = DHCP.search(msg)
            if m:
                ev.update(cat="dhcp", act="ack", src=m[1], mac=m[2].lower(), _name=m[3])
    elif prog.startswith(("dropbear", "sshd", "luci", "uhttpd", "lighttpd", "httpd")):
        ip = IP.search(msg)
        if ip and (BAD.search(msg) or GOOD.search(msg)):
            u = USER.search(msg)
            ev.update(cat="auth", act="fail" if BAD.search(msg) else "ok", src=ip[0], user=u[1] if u else "",
                      dport=22 if prog.startswith(("dropbear", "sshd")) else 80)
    elif prog.startswith("hostapd"):
        m = STA.search(msg)
        if m:
            ev.update(cat="wifi", act="join", mac=m[1].lower())
    return ev


# ------------------------------------------------------------------ SIEM core
class SIEM:
    def __init__(self, cfg):
        self.cfg = cfg
        self.lock, self.dblock = threading.Lock(), threading.Lock()
        self.q = queue.Queue(maxsize=100000)
        self.win = defaultdict(lambda: deque(maxlen=5000))
        self.last, self.assets, self.iocs = {}, {}, set()
        self.stats = {"events": 0, "alerts": 0, "started": time.time()}
        self.cleaned = self.purged = 0
        os.makedirs(os.path.dirname(cfg["db"]) or ".", exist_ok=True)
        self.db = sqlite3.connect(cfg["db"], timeout=10, check_same_thread=False)
        self.db.execute("PRAGMA journal_mode=WAL")
        self.db.execute("PRAGMA synchronous=NORMAL")
        self.db.executescript(SCHEMA)
        with open(cfg["rules"]) as f:
            self.rules = json.load(f)
        self.load_iocs()
        row = self.db.execute("SELECT v FROM meta WHERE k='first_run'").fetchone()
        if row:
            first = float(row[0])
        else:
            first = time.time()
            self.db.execute("INSERT INTO meta VALUES('first_run',?)", (str(first),))
            self.db.commit()
        self.learn_until = first + cfg["learning_minutes"] * 60
        for mac, seen in self.db.execute("SELECT mac,last_seen FROM assets"):
            self.assets[mac] = seen

    # ---- storage helpers (shared with web UI)
    def query(self, sql, args=()):
        with self.dblock:
            return self.db.execute(sql, args).fetchall()

    def execute(self, sql, args=()):
        with self.dblock:
            cur = self.db.execute(sql, args)
            self.db.commit()
            return cur.rowcount

    def load_iocs(self):
        s, p = set(), self.cfg["iocs"]
        if os.path.exists(p):
            for line in open(p, errors="ignore"):
                line = line.split("#")[0].strip()
                if line:
                    s.add(line.split()[-1].lower())
        self.iocs = s

    def is_ioc(self, v):
        v = v.lower()
        if v in self.iocs:
            return True
        p = v.split(".")
        return any(".".join(p[i:]) in self.iocs for i in range(1, len(p) - 1))

    # ---- ingest + correlation
    def ingest(self, line, host="", ts=None):
        ts = ts or time.time()
        ev = parse(line, host, ts)
        self.stats["events"] += 1
        if ev["cat"] in self.cfg["store_cats"]:
            try:
                self.q.put_nowait(("ev", ts, host, ev["prog"], ev["cat"], ev["act"], ev["src"], ev["dst"],
                                   ev["sport"], ev["dport"], ev["user"], ev["mac"], ev["domain"], ev["msg"]))
            except queue.Full:
                pass
        with self.lock:
            if ts - self.cleaned > 300:
                self.cleanup(ts)
            self.evaluate(ev)
        return ev

    def cleanup(self, t):
        self.cleaned = t
        for k in [k for k, d in self.win.items() if not d or d[-1][0] < t - 3600]:
            del self.win[k]
        for k in [k for k, v in self.last.items() if v < t - 86400]:
            del self.last[k]

    def push(self, key, ts, val, window):
        d = self.win[key]
        d.append((ts, val))
        return self.peek(key, ts, window)

    def peek(self, key, ts, window):
        d = self.win[key]
        while d and d[0][0] < ts - window:
            d.popleft()
        return d

    @staticmethod
    def match(m, ev):
        for k, v in m.items():
            if k == "src_scope":
                if scope(ev["src"]) != v:
                    return False
            elif ev.get(k) not in (v if isinstance(v, list) else [v]):
                return False
        return True

    def track_asset(self, ev):
        mac, ts = ev["mac"], ev["ts"]
        if not mac:
            return
        if mac not in self.assets:
            self.assets[mac] = ts
            self.q.put(("asset", mac, ev["src"], ev["_name"], ts))
            if ts > self.learn_until:
                for r in self.rules:
                    if r["type"] == "new_asset" and r.get("enabled", True):
                        self.fire(r, mac, f"MAC {mac} ip={ev['src'] or '?'} name={ev['_name'] or '?'}", ts)
        elif ts - self.assets[mac] > 3600:
            self.assets[mac] = ts
            self.q.put(("asset", mac, ev["src"], ev["_name"], ts))

    def evaluate(self, ev):
        ts = ev["ts"]
        self.track_asset(ev)
        for r in self.rules:
            if not r.get("enabled", True) or r["type"] == "new_asset":
                continue
            t = r["type"]
            if t == "ioc":
                for f in r["fields"]:
                    v = ev.get(f)
                    if v and self.is_ioc(v):
                        self.fire(r, v, f"{f}={v} is on the IOC list (src={ev['src']} dst={ev['dst']})", ts)
                continue
            g = ev.get(r.get("group_by", "src")) or "-"
            w = r.get("window", 60)
            if t == "sequence":
                if self.match(r["first"], ev):
                    self.push((r["id"], g, "f"), ts, 1, w)
                elif self.match(r["then"], ev):
                    d = self.peek((r["id"], g, "f"), ts, w)
                    if len(d) >= r.get("first_count", 1):
                        self.fire(r, g, f"{len(d)} preceding events followed by match within {w}s", ts)
                        d.clear()
                continue
            if not self.match(r.get("match", {}), ev):
                continue
            if t == "threshold":
                d = self.push((r["id"], g), ts, 1, w)
                if len(d) >= r["count"]:
                    self.fire(r, g, f"{len(d)} events in {w}s", ts)
            elif t == "distinct":
                d = self.push((r["id"], g), ts, ev.get(r["distinct"]), w)
                n = len({x for _, x in d})
                if n >= r["count"]:
                    self.fire(r, g, f"{n} distinct {r['distinct']} values in {w}s", ts)

    def fire(self, r, group, detail, ts):
        k = f"{r['id']}:{group}"
        new = ts - self.last.get(k, 0) > self.cfg["alert_cooldown"]
        if new:
            self.last[k] = ts
            self.stats["alerts"] += 1
            print(f"ALERT [{r['sev']}] {r['name']} | {group} | {detail}", flush=True)
            if r["sev"] in self.cfg["notify_levels"]:
                threading.Thread(target=self.notify, args=(r, group, detail), daemon=True).start()
        self.q.put(("alert", ts, r["id"], r["name"], r["sev"], str(group), detail[:300], r.get("mitre", ""), k, new))

    def notify(self, r, group, detail):
        c, title, text = self.cfg, f"HomeSIEM [{r['sev']}] {r['name']}", f"{group}: {detail}"
        try:
            if c["ntfy_url"]:
                hdr = {"Title": title.encode("ascii", "ignore").decode()}
                urllib.request.urlopen(urllib.request.Request(c["ntfy_url"], text.encode(), hdr), timeout=10)
            if c["telegram_token"]:
                data = urllib.parse.urlencode({"chat_id": c["telegram_chat"], "text": title + "\n" + text}).encode()
                urllib.request.urlopen(f"https://api.telegram.org/bot{c['telegram_token']}/sendMessage", data, timeout=10)
            if c["webhook_url"]:
                body = json.dumps({"title": title, "rule": r["id"], "group": group, "detail": detail}).encode()
                urllib.request.urlopen(urllib.request.Request(
                    c["webhook_url"], body, {"Content-Type": "application/json"}), timeout=10)
        except Exception as e:
            print("notify failed:", e, flush=True)

    # ---- batched writer (SD-card friendly)
    def flush(self):
        b = defaultdict(list)
        try:
            while True:
                it = self.q.get_nowait()
                b[it[0]].append(it[1:])
        except queue.Empty:
            pass
        with self.dblock:
            db = self.db
            if b["ev"]:
                db.executemany("INSERT INTO events(ts,host,prog,cat,act,src,dst,sport,dport,user,mac,domain,msg) "
                               "VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)", b["ev"])
            for ts, rid, title, sev, grp, detail, mitre, key, new in b["alert"]:
                if not new and db.execute(
                        "UPDATE alerts SET count=count+1,last_seen=? WHERE id=(SELECT MAX(id) FROM alerts "
                        "WHERE dedup=? AND status!='closed')", (ts, key)).rowcount:
                    continue
                db.execute("INSERT INTO alerts(ts,last_seen,rule_id,title,sev,grp,detail,mitre,count,status,dedup) "
                           "VALUES(?,?,?,?,?,?,?,?,1,'open',?)", (ts, ts, rid, title, sev, grp, detail, mitre, key))
            if b["asset"]:
                db.executemany(
                    "INSERT INTO assets VALUES(?,?,?,?,?) ON CONFLICT(mac) DO UPDATE SET last_seen=excluded.last_seen,"
                    "ip=CASE WHEN excluded.ip!='' THEN excluded.ip ELSE ip END,"
                    "name=CASE WHEN excluded.name!='' THEN excluded.name ELSE name END",
                    [(m, ip, n, t, t) for m, ip, n, t in b["asset"]])
            if time.time() - self.purged > 3600:
                cut = time.time() - self.cfg["retention_days"] * 86400
                db.execute("DELETE FROM events WHERE ts<?", (cut,))
                db.execute("DELETE FROM alerts WHERE ts<? AND status='closed'", (cut,))
                self.purged = time.time()
            db.commit()

    def writer_loop(self):
        while True:
            time.sleep(5)
            try:
                self.flush()
            except Exception as e:
                print("flush error:", e, flush=True)


# ------------------------------------------------------------------ collectors
class _TCP(socketserver.ThreadingTCPServer):
    daemon_threads = True
    allow_reuse_address = True


def start_listeners(siem):
    cfg = siem.cfg

    def ok(ip):
        return not cfg["allowed_sources"] or ip in cfg["allowed_sources"]

    usock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    usock.bind(("0.0.0.0", cfg["syslog_udp_port"]))

    def udp_loop():
        while True:
            data, addr = usock.recvfrom(8192)
            if ok(addr[0]):
                for line in data.decode("utf-8", "replace").splitlines():
                    if line.strip():
                        try:
                            siem.ingest(line, addr[0])
                        except Exception as e:
                            print("ingest error:", e, flush=True)

    class Handler(socketserver.StreamRequestHandler):
        def handle(self):
            ip = self.client_address[0]
            if not ok(ip):
                return
            self.request.settimeout(300)
            try:
                while True:
                    raw = self.rfile.readline(8192)
                    if not raw:
                        break
                    if raw.strip():
                        siem.ingest(raw.decode("utf-8", "replace"), ip)
            except OSError:
                pass

    tsrv = _TCP(("0.0.0.0", cfg["syslog_tcp_port"]), Handler)
    threading.Thread(target=udp_loop, daemon=True).start()
    threading.Thread(target=tsrv.serve_forever, daemon=True).start()
    return usock, tsrv


def load_config(path=None):
    cfg = dict(DEFAULTS)
    path = path or os.path.join(BASE, "config.json")
    if os.path.exists(path):
        with open(path) as f:
            cfg.update(json.load(f))
    for k in ("db", "rules", "iocs"):
        if not os.path.isabs(cfg[k]):
            cfg[k] = os.path.join(BASE, cfg[k])
    return cfg


def main():
    path = sys.argv[sys.argv.index("--config") + 1] if "--config" in sys.argv else None
    cfg = load_config(path)
    if cfg["web_password"] == "changeme":
        print("WARNING: change web_password in config.json", flush=True)
    siem = SIEM(cfg)
    threading.Thread(target=siem.writer_loop, daemon=True).start()
    usock, tsrv = start_listeners(siem)
    import web
    srv = web.make_server(siem)
    print(f"syslog udp/tcp {cfg['syslog_udp_port']} | dashboard http://{cfg['web_bind']}:{cfg['web_port']}/", flush=True)
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        siem.flush()


if __name__ == "__main__":
    main()
