#!/usr/bin/env python3
"""End-to-end self test: simulated attacks -> alerts -> web UI. Run: python3 selftest.py"""
import base64, os, socket, sys, tempfile, threading, time, urllib.error, urllib.parse, urllib.request
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import homesiem, web

tmp = tempfile.mkdtemp()
cfg = homesiem.load_config()
cfg.update(db=os.path.join(tmp, "t.db"), learning_minutes=0, web_bind="127.0.0.1", web_port=0,
           syslog_udp_port=0, syslog_tcp_port=0, web_password="pw")
s = homesiem.SIEM(cfg)
time.sleep(0.05)
H = "<30>Nov 10 12:00:00 "
for i in range(6):   # brute force from 8.8.8.8
    s.ingest(H + "dropbear[1]: Bad password attempt for 'root' from 8.8.8.8:4000%d" % i, "r")
for i in range(3):   # failures then success -> R002 + R003
    s.ingest(H + "dropbear[1]: Bad password attempt for 'root' from 1.1.1.1:5000", "r")
s.ingest(H + "dropbear[1]: Password auth succeeded for 'root' from 1.1.1.1:5001", "r")
for p in range(20, 40):  # port scan
    s.ingest(H + "kernel: [1.0] reject wan in: IN=wan SRC=9.9.9.9 DST=203.0.113.5 PROTO=TCP SPT=1 DPT=%d" % p, "r")
for p in range(20, 40):  # LAN scan
    s.ingest(H + "kernel: [1.0] IN=br-lan SRC=192.168.1.50 DST=192.168.1.1 PROTO=TCP SPT=1 DPT=%d" % p, "r")
s.ingest(H + "dnsmasq-dhcp[1]: DHCPACK(br-lan) 192.168.1.77 aa:bb:cc:dd:ee:ff phone", "r")
s.ingest(H + "dnsmasq[1]: query[A] sub.evil-c2.example from 192.168.1.50", "r")
for _ in range(3):
    s.ingest(H + "dnsmasq[1]: query[A] qzxvbnmasdfghjklwertyuiopxcv.com from 192.168.1.50", "r")
s.ingest(H + "hostapd: wlan0: AP-STA-CONNECTED 11:22:33:44:55:66", "r")
s.flush()
ids = {r[0] for r in s.query("SELECT rule_id FROM alerts")}
want = {"R001", "R002", "R003", "R004", "R005", "R006", "R008", "R009"}
assert want <= ids, "missing rules: %s" % (want - ids)
assert s.query("SELECT COUNT(*) FROM assets")[0][0] == 2
assert s.query("SELECT COUNT(*) FROM events WHERE cat='auth'")[0][0] == 10

usock, tsrv = homesiem.start_listeners(s)   # UDP + TCP collectors
usock.sendto((H + "dropbear[1]: Bad password attempt for 'x' from 7.7.7.7:1").encode(), ("127.0.0.1", usock.getsockname()[1]))
c = socket.create_connection(("127.0.0.1", tsrv.server_address[1]))
c.sendall((H + "dropbear[1]: Bad password attempt for 'y' from 7.7.7.8:1\n").encode()); c.close()
time.sleep(0.5); s.flush()
assert s.query("SELECT COUNT(*) FROM events WHERE src IN ('7.7.7.7','7.7.7.8')")[0][0] == 2

srv = web.make_server(s)
threading.Thread(target=srv.serve_forever, daemon=True).start()
base = "http://127.0.0.1:%d" % srv.server_address[1]
auth = {"Authorization": "Basic " + base64.b64encode(b"admin:pw").decode()}
get = lambda p: urllib.request.urlopen(urllib.request.Request(base + p, headers=auth), timeout=5)
for p in ("/", "/alerts", "/alerts?status=all", "/search?q=src:8.8.8.8+cat:auth", "/search?q=src:192.168.*",
          "/assets", "/rules", "/export/alerts.csv", "/export/events.csv?q=dport:22"):
    r = get(p); assert r.status == 200, p
assert b"R001" in get("/alerts").read()
try:
    urllib.request.urlopen(base + "/", timeout=5); raise SystemExit("auth not enforced")
except urllib.error.HTTPError as e:
    assert e.code == 401
body = get("/alerts").read().decode()
csrf = body.split("name=csrf value='")[1].split("'")[0]
aid = int(body.split("/alerts/")[1].split("/")[0])
class NoRedir(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *a, **k): return None
op = urllib.request.build_opener(NoRedir)
def post(data):
    req = urllib.request.Request(base + "/alerts/%d/ack" % aid, urllib.parse.urlencode(data).encode(), auth)
    try: return op.open(req, timeout=5).status
    except urllib.error.HTTPError as e: return e.code
assert post({"csrf": "bad"}) == 403 and post({"csrf": csrf}) == 303
assert s.query("SELECT status FROM alerts WHERE id=?", (aid,))[0][0] == "ack"
print("ALL TESTS PASSED  (alerts fired: %s)" % ", ".join(sorted(ids)))
