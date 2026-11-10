"""HomeSIEM web UI: overview, alerts (ack/close), search, assets, rules, CSV export. Stdlib only."""
import base64, csv, hmac, html, io, re, secrets, shlex, time, urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

FIELDS = {"src", "dst", "sport", "dport", "user", "mac", "domain", "cat", "act", "prog", "host"}
CSS = ("body{font:14px system-ui,sans-serif;background:#111;color:#ddd;margin:0}main{padding:1em;max-width:1200px;margin:auto}"
       "nav{background:#1c1c1c;padding:.6em 1em}nav a{color:#8cf;margin-right:1em;text-decoration:none}"
       "table{border-collapse:collapse;width:100%;margin-bottom:1em}td,th{border-bottom:1px solid #333;padding:4px 8px;"
       "text-align:left;vertical-align:top}th{color:#8af}h2{color:#fff}.cards{display:flex;gap:1em;flex-wrap:wrap}"
       ".card{background:#1c1c1c;padding:.8em 1.2em;border-radius:6px}.card b{font-size:1.6em;display:block}"
       ".critical,.high{color:#f66}.medium{color:#fb4}.low{color:#9c9}input{background:#222;color:#ddd;border:1px solid #444;"
       "padding:4px}button{background:#245;color:#fff;border:0;padding:3px 8px;margin-right:3px;cursor:pointer}")
NAV = [("/", "Overview"), ("/alerts", "Alerts"), ("/search", "Search"), ("/assets", "Assets"), ("/rules", "Rules")]


class Raw(str):
    pass


def esc(x):
    return x if isinstance(x, Raw) else html.escape(str(x))


def ft(t):
    return time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(t))


def table(head, rows, cls_col=None):
    out = "<table><tr>" + "".join(f"<th>{esc(h)}</th>" for h in head) + "</tr>"
    for r in rows:
        c = f" class='{esc(r[cls_col])}'" if cls_col is not None else ""
        out += f"<tr{c}>" + "".join(f"<td>{esc(v)}</td>" for v in r) + "</tr>"
    return out + "</table>"


def build_where(q, hours):
    where, args = ["ts>?"], [time.time() - hours * 3600]
    try:
        toks = shlex.split(q)
    except ValueError:
        toks = q.split()
    for t in toks:
        k, _, v = t.partition(":")
        if v and k in FIELDS:
            if "*" in v:
                where.append(f"{k} LIKE ?")
                args.append(v.replace("*", "%"))
            else:
                where.append(f"{k}=?")
                args.append(v)
        else:
            where.append("msg LIKE ?")
            args.append(f"%{t}%")
    return " AND ".join(where), args


def chart(rows):
    base = int(time.time() // 3600) * 3600 - 23 * 3600
    vals = {int(b): c for b, c in rows}
    series = [vals.get(base + i * 3600, 0) for i in range(24)]
    mx = max(series) or 1
    bars = "".join(
        f"<rect x='{i * 30 + 2}' y='{110 - int(100 * v / mx)}' width='26' height='{int(100 * v / mx)}' fill='#4a9'>"
        f"<title>{time.strftime('%H:00', time.localtime(base + i * 3600))} = {v}</title></rect>"
        for i, v in enumerate(series))
    return Raw(f"<svg viewBox='0 0 720 115' width='100%'>{bars}</svg>")


def make_server(siem):
    cfg, csrf = siem.cfg, secrets.token_hex(16)
    ok_user, ok_pass = cfg["web_user"].encode(), cfg["web_password"].encode()

    def page(title, body):
        nav = "".join(f"<a href='{u}'>{n}</a>" for u, n in NAV)
        return (f"<!doctype html><meta charset=utf-8><meta name=viewport content='width=device-width,initial-scale=1'>"
                f"<title>HomeSIEM</title><style>{CSS}</style><nav><b>HomeSIEM</b> &nbsp; {nav}</nav>"
                f"<main><h2>{esc(title)}</h2>{body}</main>")

    def overview():
        day = time.time() - 86400
        n_ev = siem.query("SELECT COUNT(*) FROM events WHERE ts>?", (day,))[0][0]
        n_al = siem.query("SELECT COUNT(*) FROM alerts WHERE status='open'")[0][0]
        n_as = siem.query("SELECT COUNT(*) FROM assets")[0][0]
        per_h = siem.query("SELECT CAST(ts/3600 AS INTEGER)*3600,COUNT(*) FROM events WHERE ts>? GROUP BY 1", (day,))
        top = siem.query("SELECT src,COUNT(*),COUNT(DISTINCT dport) FROM events WHERE cat='fw' AND ts>? "
                         "GROUP BY src ORDER BY 2 DESC LIMIT 10", (day,))
        al = [(ft(r[0]), r[1], r[2], r[3], r[4]) for r in siem.query(
            "SELECT last_seen,sev,title,grp,count FROM alerts WHERE status='open' ORDER BY last_seen DESC LIMIT 10")]
        cards = "".join(f"<div class=card><b>{v}</b>{k}</div>" for k, v in [
            ("events stored (24h)", n_ev), ("open alerts", n_al), ("assets", n_as),
            ("events received", siem.stats["events"]),
            ("uptime (min)", int((time.time() - siem.stats["started"]) / 60))])
        return (f"<div class=cards>{cards}</div><h3>Events per hour (24h)</h3>{chart(per_h)}"
                f"<h3>Open alerts</h3>{table(['Last seen', 'Sev', 'Rule', 'Source', 'Count'], al, 1)}"
                f"<h3>Top firewall-drop sources (24h)</h3>{table(['Source', 'Drops', 'Distinct ports'], top)}")

    def alerts(qs):
        st = qs.get("status", ["open"])[0]
        where, args = ("1=1", ()) if st == "all" else ("status=?", (st,))
        rows = []
        for i, ts, ls, rid, title, sev, grp, detail, mitre, cnt, status in siem.query(
                "SELECT id,ts,last_seen,rule_id,title,sev,grp,detail,mitre,count,status FROM alerts WHERE " + where +
                " ORDER BY last_seen DESC LIMIT 200", args):
            btn = "".join(
                f"<form method=post action='/alerts/{i}/{a}' style='display:inline'>"
                f"<input type=hidden name=csrf value='{csrf}'><button>{a}</button></form>"
                for a in ("ack", "close", "open") if a != {"open": "open", "ack": "ack", "closed": "close"}[status])
            rows.append((ft(ts), ft(ls), sev, f"{rid} {title}", grp, detail, mitre, cnt, status, Raw(btn)))
        links = " | ".join(f"<a href='/alerts?status={s}' style='color:#8cf'>{s}</a>" for s in ("open", "ack", "closed", "all"))
        head = ["First", "Last", "Sev", "Rule", "Group", "Detail", "MITRE", "#", "Status", ""]
        return f"<p>{links} | <a href='/export/alerts.csv' style='color:#8cf'>CSV</a></p>" + table(head, rows, 2)

    def search(qs):
        q = qs.get("q", [""])[0]
        try:
            hours = max(1, min(720, int(qs.get("hours", ["24"])[0])))
        except ValueError:
            hours = 24
        where, args = build_where(q, hours)
        rows = [(ft(r[0]),) + r[1:] for r in siem.query(
            "SELECT ts,cat,act,src,dst,dport,user,mac,domain,msg FROM events WHERE " + where +
            " ORDER BY ts DESC LIMIT 200", args)]
        form = (f"<form><input name=q value='{esc(q)}' size=50 placeholder='src:1.2.3.4 cat:auth act:fail dport:22 text'> "
                f"hours <input name=hours value={hours} size=4> <button>Search</button> "
                f"<a href='/export/events.csv?{urllib.parse.urlencode({'q': q, 'hours': hours})}' style='color:#8cf'>CSV</a></form>")
        head = ["Time", "Cat", "Act", "Src", "Dst", "Port", "User", "MAC", "Domain", "Message"]
        return form + f"<p>{len(rows)} result(s) (max 200). Fields: {', '.join(sorted(FIELDS))}; use * as wildcard.</p>" + table(head, rows)

    def assets():
        rows = [(m, ip, n, ft(a), ft(b)) for m, ip, n, a, b in siem.query(
            "SELECT mac,ip,name,first_seen,last_seen FROM assets ORDER BY last_seen DESC")]
        return table(["MAC", "IP", "Name", "First seen", "Last seen"], rows)

    def rules():
        rows = [(r["id"], r["name"], r["sev"], r["type"], r.get("mitre", ""), r.get("enabled", True)) for r in siem.rules]
        return table(["ID", "Name", "Sev", "Type", "MITRE", "Enabled"], rows, 2) + f"<p>IOCs loaded: {len(siem.iocs)}</p>"

    def to_csv(head, rows):
        buf = io.StringIO()
        w = csv.writer(buf)
        w.writerow(head)
        w.writerows(rows)
        return buf.getvalue()

    class H(BaseHTTPRequestHandler):
        def log_message(self, *a):
            pass

        def send(self, code, body, ctype="text/html; charset=utf-8", extra=()):
            data = body.encode()
            self.send_response(code)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(data)))
            self.send_header("X-Frame-Options", "DENY")
            for k, v in extra:
                self.send_header(k, v)
            self.end_headers()
            self.wfile.write(data)

        def authed(self):
            try:
                u, p = base64.b64decode(self.headers.get("Authorization", "").split(" ", 1)[1]).split(b":", 1)
                if hmac.compare_digest(u, ok_user) & hmac.compare_digest(p, ok_pass):
                    return True
            except Exception:
                pass
            self.send(401, "Authentication required", extra=[("WWW-Authenticate", 'Basic realm="HomeSIEM"')])
            return False

        def do_GET(self):
            if not self.authed():
                return
            u = urllib.parse.urlparse(self.path)
            qs = urllib.parse.parse_qs(u.query)
            try:
                if u.path == "/":
                    self.send(200, page("Overview", overview()))
                elif u.path == "/alerts":
                    self.send(200, page("Alerts", alerts(qs)))
                elif u.path == "/search":
                    self.send(200, page("Search events", search(qs)))
                elif u.path == "/assets":
                    self.send(200, page("Assets", assets()))
                elif u.path == "/rules":
                    self.send(200, page("Detection rules", rules()))
                elif u.path == "/export/alerts.csv":
                    rows = siem.query("SELECT id,ts,last_seen,rule_id,title,sev,grp,detail,mitre,count,status FROM alerts ORDER BY id")
                    self.send(200, to_csv(["id", "ts", "last_seen", "rule", "title", "sev", "group", "detail", "mitre", "count", "status"], rows), "text/csv")
                elif u.path == "/export/events.csv":
                    where, args = build_where(qs.get("q", [""])[0], 24 if not qs.get("hours", [""])[0].isdigit() else int(qs["hours"][0]))
                    rows = siem.query("SELECT ts,host,cat,act,src,dst,sport,dport,user,mac,domain,msg FROM events WHERE " + where + " ORDER BY ts DESC LIMIT 20000", args)
                    self.send(200, to_csv(["ts", "host", "cat", "act", "src", "dst", "sport", "dport", "user", "mac", "domain", "msg"], rows), "text/csv")
                else:
                    self.send(404, page("Not found", ""))
            except Exception as e:
                self.send(500, page("Error", esc(e)))

        def do_POST(self):
            if not self.authed():
                return
            m = re.fullmatch(r"/alerts/(\d+)/(ack|close|open)", self.path)
            try:
                n = min(int(self.headers.get("Content-Length", 0)), 2000)
            except ValueError:
                n = 0
            form = urllib.parse.parse_qs(self.rfile.read(n).decode("utf-8", "replace"))
            if not m or form.get("csrf", [""])[0] != csrf:
                return self.send(403, "Forbidden")
            status = {"ack": "ack", "close": "closed", "open": "open"}[m[2]]
            siem.execute("UPDATE alerts SET status=? WHERE id=?", (status, int(m[1])))
            self.send(303, "", extra=[("Location", "/alerts")])

    return ThreadingHTTPServer((cfg["web_bind"], cfg["web_port"]), H)
