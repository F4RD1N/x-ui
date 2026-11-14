#!/usr/bin/env python3
# Helper of e2e.sh (udpRouteEachDestination): config generators, the remote
# UDP recorder, the per-path test cases and the load sender. Run with -I.
#
#   helper.py gen-server TEMPLATE OUT on|off|absent e2e|load UUID SSPASS
#   helper.py gen-client OUT UUID SSPASS
#   helper.py recorder LOG PORT...
#   helper.py cases SOCKSPORT PATH VARIANT RECLOG
#   helper.py load HOST PORT NDEST SECS RATE
import json, os, socket, struct, sys, time

SRV = "10.201.0.1"  # server namespace, side facing the client
PATHS = {"mux": 20001, "xudp": 20002, "socks": 20003, "ss": 20004}
SNIFF = {"enabled": True, "destOverride": ["http", "tls", "quic", "fakedns"], "metadataOnly": False, "routeOnly": False}

# Public, non-reserved addresses; the remote namespace owns them.
BAD = "45.33.1.1"        # Linode, on no list of the template
QUIC_IP = "45.33.2.2"    # on no IP list; i.instagram.com resolves to it in the server ns
QUIC_BAD = "45.33.2.3"
DNS = "8.8.8.8"          # rule 11 (8.8.8.0/24) and rule 19 (resolvers, :53)
DNS2 = "8.8.4.4"         # rule 11 and rule 19
GAME = "5.42.160.1"      # games-ip
APP = "23.89.1.1"        # apps-ip
APPLE = "17.253.1.1"     # apps-ip-apple: 17/8 only on its port list (3478-3497, ...)

# Used when the real template is not there: the same shape (blocked first,
# no catch-all, only listed destinations to direct).
FALLBACK_ROUTING = {"domainStrategy": "AsIs", "rules": [
    {"type": "field", "inboundTag": ["api"], "outboundTag": "api"},
    {"type": "field", "outboundTag": "blocked", "ip": ["10.0.0.0/8", "127.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "100.64.0.0/10"]},
    {"type": "field", "ip": ["8.8.4.0/24", "8.8.8.0/24", "31.13.64.0/18"], "outboundTag": "direct"},
    {"type": "field", "ruleTag": "games-ip", "ip": ["5.42.160.0/20"], "outboundTag": "direct"},
    {"type": "field", "ruleTag": "apps-ip", "ip": ["23.89.0.0/17"], "outboundTag": "direct"},
    {"type": "field", "ruleTag": "apps-ip-apple", "ip": ["17.0.0.0/8"], "port": "80,123,443,2197,3478-3497,4398,5223,16384-16472", "outboundTag": "direct"},
    {"type": "field", "ruleTag": "web-domain", "domain": ["domain:instagram.com"], "outboundTag": "direct"},
    {"type": "field", "ruleTag": "dns-resolvers-only", "port": "53", "network": "UDP", "ip": ["8.8.8.8", "8.8.4.4"], "outboundTag": "direct"}]}


def gen_server(template, out, setting, mode, uuid, sspass):
    if os.path.exists(template):
        c = json.load(open(template))
    else:
        c = {"api": {"services": ["StatsService"], "tag": "api"}, "stats": {},
             "inbounds": [{"listen": "127.0.0.1", "port": 62789, "protocol": "tunnel", "settings": {"address": "127.0.0.1"}, "tag": "api"}],
             "policy": {"system": {"statsOutboundDownlink": True, "statsOutboundUplink": True}},
             "outbounds": [{"tag": "blocked", "protocol": "blackhole"}, {"tag": "direct", "protocol": "freedom", "settings": {"domainStrategy": "AsIs"}}],
             "routing": FALLBACK_ROUTING}
    # Keep routing, outbounds, policy, api, stats, metrics; keep only the api inbound.
    ibs = [i for i in c.get("inbounds", []) if i.get("tag") == "api"]
    ibs += [
        {"tag": "in-vless", "listen": SRV, "port": 10001, "protocol": "vless",
         "settings": {"clients": [{"id": uuid, "email": "e2e-vless", "flow": ""}], "decryption": "none"},
         "streamSettings": {"network": "tcp", "security": "none"}, "sniffing": SNIFF},
        {"tag": "in-socks", "listen": SRV, "port": 10002, "protocol": "socks",
         "settings": {"auth": "noauth", "udp": True, "ip": SRV}, "sniffing": SNIFF},
        {"tag": "in-ss", "listen": SRV, "port": 10003, "protocol": "shadowsocks",
         "settings": {"method": "aes-128-gcm", "password": sspass, "network": "tcp,udp"}, "sniffing": SNIFF},
    ]
    c["inbounds"] = ibs
    log = c.setdefault("log", {})
    log["loglevel"] = "info" if mode == "e2e" else "warning"
    log["access"] = "none"
    log["error"] = ""
    for o in c["outbounds"]:
        if o.get("tag") == "direct":
            s = o.setdefault("settings", {})
            s.pop("udpRouteEachDestination", None)
            if setting != "absent":
                s["udpRouteEachDestination"] = setting == "on"
    json.dump(c, open(out, "w"), indent=1)


def gen_client(out, uuid, sspass):
    vnext = lambda: {"vnext": [{"address": SRV, "port": 10001, "users": [{"id": uuid, "encryption": "none", "flow": ""}]}]}
    xudp = vnext(); xudp["packetEncoding"] = "xudp"
    obs = [
        {"tag": "o-mux", "protocol": "vless", "settings": vnext(),
         "mux": {"enabled": True, "concurrency": 8, "xudpConcurrency": 16, "xudpProxyUDP443": "allow"}},
        {"tag": "o-xudp", "protocol": "vless", "settings": xudp},
        {"tag": "o-socks", "protocol": "socks", "settings": {"servers": [{"address": SRV, "port": 10002}]}},
        {"tag": "o-ss", "protocol": "shadowsocks", "settings": {"servers": [{"address": SRV, "port": 10003, "method": "aes-128-gcm", "password": sspass}]}},
    ]
    ibs = [{"tag": "c-" + p, "listen": "127.0.0.1", "port": port, "protocol": "socks", "settings": {"auth": "noauth", "udp": True, "ip": "127.0.0.1"}}
           for p, port in PATHS.items()]
    rules = [{"type": "field", "inboundTag": ["c-" + p], "outboundTag": "o-" + p} for p in PATHS]
    json.dump({"log": {"loglevel": "warning"}, "inbounds": ibs, "outbounds": obs, "routing": {"rules": rules}}, open(out, "w"), indent=1)


def recorder(logf, ports):
    # Binds 0.0.0.0:port (the remote ns routes the public prefixes to lo),
    # logs "dst:port hex(payload)" and echoes from the address it was sent to.
    import selectors
    PKT = 8  # IP_PKTINFO
    sel = selectors.DefaultSelector()
    for p in ports:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.setsockopt(socket.IPPROTO_IP, PKT, 1)
        s.bind(("0.0.0.0", int(p)))
        sel.register(s, selectors.EVENT_READ, int(p))
    f = open(logf, "a", buffering=1)
    while True:
        for key, _ in sel.select():
            s, port = key.fileobj, key.data
            data, anc, _, src = s.recvmsg(4096, socket.CMSG_SPACE(12))
            dst = "?"
            for lvl, typ, cd in anc:
                if lvl == socket.IPPROTO_IP and typ == PKT:
                    dst = socket.inet_ntoa(cd[8:12]); spec = cd[8:12]
            f.write("%s:%d %s\n" % (dst, port, data.hex()))
            try:
                s.sendmsg([data[:512]], [(socket.IPPROTO_IP, PKT, struct.pack("i4s4s", 0, spec, b"\0" * 4))], 0, src)
            except Exception:
                pass


# --- QUIC Initial with a chosen SNI (same as whitelist-2ndvpn/quicbuild.py) ---
def quic_initial(sni):
    import hashlib, hmac
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    SALT = bytes.fromhex("38762cf7f55934b34d179ae6a4c80cadccbb7f0a")

    def ext_(secret, label, n):
        full = b"tls13 " + label.encode(); info = struct.pack(">H", n) + bytes([len(full)]) + full + b"\x00"
        out = b""; t = b""; i = 1
        while len(out) < n:
            t = hmac.new(secret, t + info + bytes([i]), hashlib.sha256).digest(); out += t; i += 1
        return out[:n]

    s = sni.encode()
    sni_ext = struct.pack(">HH", 0, len(s) + 5) + struct.pack(">HBH", len(s) + 3, 0, len(s)) + s
    exts = (sni_ext + b"\x00\x10" + struct.pack(">H", 5) + b"\x00\x03\x02h3" + b"\x00\x2b\x00\x03\x02\x03\x04" +
            b"\x00\x0a\x00\x04\x00\x02\x00\x1d" + b"\x00\x33" + struct.pack(">H", 38) + struct.pack(">H", 36) + b"\x00\x1d\x00\x20" +
            os.urandom(32) + b"\x00\x0d\x00\x04\x00\x02\x08\x04" + b"\x00\x39\x00\x04\x01\x02\x40\x64")
    body = b"\x03\x03" + os.urandom(32) + b"\x00" + b"\x00\x02\x13\x01" + b"\x01\x00" + struct.pack(">H", len(exts)) + exts
    ch = b"\x01" + struct.pack(">I", len(body))[1:] + body
    dcid = os.urandom(8); scid = os.urandom(8)
    sec = ext_(hmac.new(SALT, dcid, hashlib.sha256).digest(), "client in", 32)
    key = ext_(sec, "quic key", 16); iv = ext_(sec, "quic iv", 12); hp = ext_(sec, "quic hp", 16)
    frame = b"\x06\x00" + struct.pack(">H", 0x4000 | len(ch)) + ch
    pnl = 4
    payload = frame + b"\x00" * (1162 - len(frame))
    hdr = bytes([0xC0 | (pnl - 1)]) + b"\x00\x00\x00\x01" + bytes([8]) + dcid + bytes([8]) + scid + b"\x00" + struct.pack(">H", 0x4000 | (pnl + len(payload) + 16))
    pn_off = len(hdr); hdr += (0).to_bytes(pnl, "big")
    ct = AESGCM(key).encrypt(iv, payload, hdr)
    pkt = bytearray(hdr + ct)
    e = Cipher(algorithms.AES(hp), modes.ECB()).encryptor(); mask = e.update(bytes(pkt[pn_off + 4:pn_off + 20])) + e.finalize()
    pkt[0] ^= mask[0] & 0x0F
    for i in range(pnl):
        pkt[pn_off + i] ^= mask[1 + i]
    return bytes(pkt), dcid


def dnsq(label):
    q = struct.pack(">HHHHHH", 0x1234, 0x0100, 1, 0, 0, 0)
    for l in (label + ".example.com").split("."):
        q += bytes([len(l)]) + l.encode()
    return q + b"\x00\x00\x01\x00\x01"


class Assoc:
    """One SOCKS5 UDP association = one UDP session through the client Xray."""

    def __init__(self, port):
        self.t = socket.create_connection(("127.0.0.1", port), timeout=5)
        self.t.sendall(b"\x05\x01\x00"); self.t.recv(2)
        self.t.sendall(b"\x05\x03\x00\x01\x00\x00\x00\x00\x00\x00")
        r = self.t.recv(10)
        self.relay = (socket.inet_ntoa(r[4:8]), struct.unpack(">H", r[8:10])[0])
        self.u = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); self.u.settimeout(0.05)

    def send(self, ip, port, payload):
        self.u.sendto(b"\x00\x00\x00\x01" + socket.inet_aton(ip) + struct.pack(">H", port) + payload, self.relay)

    def close(self):
        self.u.close(); self.t.close()


def cases(socksport, path, variant, reclog):
    tag = "%s-%s-%d" % (variant, path, os.getpid())
    bypass = variant == "old" or variant.endswith("off")  # the old behaviour: later destinations are not routed
    res = []

    def arrived(ip, port, marker):
        h = marker.hex() if isinstance(marker, bytes) else marker.encode().hex()
        pre = "%s:%d " % (ip, port)
        try:
            return any(l.startswith(pre) and h in l for l in open(reclog))
        except FileNotFoundError:
            return False

    def session(name, first, later, wait=0.5):
        # first: (ip, port, payload, marker, expect); later: [(ip, port, expect)]
        a = Assoc(socksport)
        ip, port, payload, marker, exp = first
        for _ in range(2):
            a.send(ip, port, payload); time.sleep(0.1)
        time.sleep(wait)
        sent = []
        for lip, lport, lexp in later:
            lab = "%s|%s|%s:%d" % (tag, name, lip, lport)
            for i in range(2):
                a.send(lip, lport, lab.encode()); time.sleep(0.08)
            sent.append((lip, lport, lab, lexp))
        time.sleep(0.8)
        a.close()
        got = arrived(ip, port, marker)
        res.append((exp == got, "%s %s first %s:%d %s (expected %s)" % (path, name, ip, port, "arrived" if got else "did not arrive", "arrive" if exp else "no arrival")))
        for lip, lport, lab, lexp in sent:
            got = arrived(lip, lport, lab)
            res.append((lexp == got, "%s %s then %s:%d %s (expected %s)" % (path, name, lip, lport, "arrived" if got else "dropped", "arrive" if lexp else "drop")))

    lab = lambda n: ("%s|%s|first" % (tag, n)).encode()
    # VLESS without mux sends UDP to :53 and :443 as plain UDP (one destination,
    # not full-cone); other ports go as XUDP. Its full-cone sessions start elsewhere.
    dport = 5353 if path == "xudp" else 53
    # 1. a first packet straight to a non-whitelisted IP is blocked everywhere
    session("direct-first", (BAD, 554, lab("df"), lab("df"), False), [])
    # 2. the reproduction: DNS first, then the same session to non-whitelisted IP:554/:15555
    q = dnsq("q" + tag.replace("-", ""))
    session("repro", (DNS, dport, q, q, True), [(BAD, 554, bypass), (BAD, 15555, bypass)])
    # 3. after DNS, whitelisted destinations keep arriving; apple 17/8 only on rule 14's ports
    q = dnsq("w" + tag.replace("-", ""))
    session("allowed-after-dns", (DNS, dport, q, q, True),
            [(GAME, 7777, True), (APP, 5000, True), (APPLE, 3478, True), (DNS2, 53, True), (APPLE, 9999, bypass)])
    # 4. QUIC: Initial with a whitelisted SNI to an IP on no list (sniffed domain routes it)
    ini, dcid = quic_initial("i.instagram.com")
    cone443 = path != "xudp"
    session("quic-instagram", (QUIC_IP, 443, ini, dcid, True),
            [(QUIC_IP, 443, True)] + ([(BAD, 15556, bypass)] if cone443 else []))
    # 5. QUIC with a non-whitelisted SNI to the same kind of IP is blocked everywhere
    ini, dcid = quic_initial("www.performancephplounge.net")
    session("quic-unlisted", (QUIC_BAD, 443, ini, dcid, False), [])
    if path == "xudp":
        # 6. no-mux DNS is plain UDP, one destination: later packets cannot leave elsewhere
        q = dnsq("p" + tag.replace("-", ""))
        session("plain-dns", (DNS, 53, q, q, True), [(BAD, 554, False)])
    for ok, msg in res:
        print(("ok   " if ok else "FAIL ") + variant + " " + msg, flush=True)


def load(host, port, ndest, secs, rate):
    # One SOCKS5 UDP association straight to the server's socks inbound;
    # spray 200-byte datagrams round-robin over ndest addresses of 23.89.0.0/17 (apps-ip).
    t = socket.create_connection((host, port), timeout=5)
    t.sendall(b"\x05\x01\x00"); t.recv(2)
    t.sendall(b"\x05\x03\x00\x01\x00\x00\x00\x00\x00\x00")
    r = t.recv(10); relay = (socket.inet_ntoa(r[4:8]), struct.unpack(">H", r[8:10])[0])
    u = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    u.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 4 << 20)
    u.connect(relay)
    pkts = []
    for i in range(ndest):
        ip = "23.89.%d.%d" % (i // 250, 1 + i % 250)
        pkts.append(b"\x00\x00\x00\x01" + socket.inet_aton(ip) + struct.pack(">H", 9000) + b"L" * 200)
    n = 0; t0 = time.time(); end = t0 + secs; batch = 64
    send = u.send
    while True:
        now = time.time()
        if now >= end:
            break
        if rate:
            due = int((now - t0) * rate)
            if n >= due:
                time.sleep(0.0005); continue
        for _ in range(batch):
            try:
                send(pkts[n % ndest])
            except (BlockingIOError, ConnectionRefusedError):
                pass
            n += 1
    print(n, flush=True)
    t.close()


if __name__ == "__main__":
    cmd, a = sys.argv[1], sys.argv[2:]
    if cmd == "gen-server":
        gen_server(*a)
    elif cmd == "gen-client":
        gen_client(*a)
    elif cmd == "recorder":
        recorder(a[0], a[1:])
    elif cmd == "cases":
        cases(int(a[0]), a[1], a[2], a[3])
    elif cmd == "load":
        load(a[0], int(a[1]), int(a[2]), float(a[3]), int(a[4]))
