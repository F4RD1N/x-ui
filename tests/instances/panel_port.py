#!/usr/bin/env python3
"""A panel port the panel cannot listen on never takes x-ui and its cores
down, and a new panel port is reserved and freed first.

Run by panel-port.sh inside a throwaway network namespace, with the panel's
database, bin and log folders in $T. Scenarios:

1. An outgoing connection has the new port as its local port. The port is
   changed through the API: the connection is closed and the port reserved.
   Another connection bound to it after the save is closed by the SIGHUP
   restart, and the panel comes up on the new port; x-ui never exits.
2. The same through "x-ui setting -port".
3. Another program listens on the new port: the API refuses it. Forced
   through the database, the SIGHUP restart is refused: the panel stays on
   its port and the cores keep running untouched (same PIDs). Setting the
   port back to the one the panel listens on is accepted.
4. The listen address is set to one the host does not have, on the same
   port: the API and the CLI refuse it, and forced through the database,
   the SIGHUP restart is refused as in 3.
5. x-ui starts while another program listens on its port: it stays up with
   its cores, and the panel listens once the port is free.
6. x-ui starts while an outgoing connection has its port: the connection is
   closed and the panel listens at once.
"""
import os
import signal
import socket
import sqlite3
import subprocess
import sys
import threading
import time

import requests

PANEL = os.environ["PANEL"]
T = os.environ["T"]
DB = os.path.join(T, "db", "x-ui.db")
LOG = os.path.join(T, "panel.log")
# Ports in the kernel's ephemeral range, where outgoing connections land.
P1, P2, P3 = 41001, 42002, 43003

results = []
procs = []  # every process started here, stopped at the end


def check(name, ok, detail=""):
    results.append((name, bool(ok)))
    print(("PASS " if ok else "FAIL ") + name + (f"  [{detail}]" if detail and not ok else ""), flush=True)


def until(pred, timeout):
    end = time.time() + timeout
    while time.time() < end:
        if pred():
            return True
        time.sleep(0.2)
    return pred()


s = requests.Session()


def answers(port):
    """The panel, not some other program, answers on port."""
    try:
        r = s.get(f"http://127.0.0.1:{port}/t/", timeout=2)
        return r.status_code == 200 and "<html" in r.text.lower()
    except requests.RequestException:
        return False


def login(port):
    r = s.post(f"http://127.0.0.1:{port}/t/login", data={"username": "t", "password": "t"}, timeout=10)
    return r.ok and r.json().get("success")


def api(port, path, **kw):
    return s.post(f"http://127.0.0.1:{port}/t{path}", timeout=30, **kw).json()


def start_panel():
    log = open(LOG, "a")
    p = subprocess.Popen([PANEL, "run"], cwd=T, stdout=log, stderr=subprocess.STDOUT)
    procs.append(p)
    return p


def stop_panel(p):
    p.send_signal(signal.SIGTERM)
    try:
        p.wait(30)
    except subprocess.TimeoutExpired:
        p.kill()
        p.wait()


def cores(p):
    """The xray cores the panel runs, by PID."""
    out = subprocess.run(["ps", "-o", "pid=,comm=", "--ppid", str(p.pid)], capture_output=True, text=True).stdout
    return sorted(int(line.split()[0]) for line in out.splitlines() if "xray" in line)


def log_text():
    """The panel's output and its log file (which a start truncates)."""
    out = ""
    for path in (LOG, os.path.join(T, "log", "3xui.log")):
        try:
            with open(path, errors="replace") as f:
                out += f.read()
        except FileNotFoundError:
            pass
    return out


def reserved():
    with open("/proc/sys/net/ipv4/ip_local_reserved_ports") as f:
        out = set()
        for part in f.read().strip().split(","):
            if "-" in part:
                a, b = part.split("-")
                out.update(range(int(a), int(b) + 1))
            elif part:
                out.add(int(part))
        return out


def can_bind(port):
    sock = socket.socket(socket.AF_INET6)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        sock.bind(("::", port))
        return True
    except OSError:
        return False
    finally:
        sock.close()


def set_db(key, value):
    db = sqlite3.connect(DB, timeout=30)
    with db:
        db.execute("UPDATE settings SET value = ? WHERE key = ?", (str(value), key))
    db.close()


class Holder:
    """An outgoing connection from 1.2.3.4:port, as a busy core's connection
    takes a port of the ephemeral range. On an error it closes the socket,
    as a program does."""

    def __init__(self, port):
        self.srv = socket.create_server(("1.2.3.4", 0))
        threading.Thread(target=self._accept, daemon=True).start()
        self.c = socket.socket()
        self.c.bind(("1.2.3.4", port))
        self.c.connect(self.srv.getsockname())
        self.err = None
        self.done = threading.Event()
        threading.Thread(target=self._read, daemon=True).start()

    def _accept(self):
        self.peers = []
        while True:
            try:
                self.peers.append(self.srv.accept()[0])
            except OSError:
                return

    def _read(self):
        try:
            self.c.recv(1)
            self.err = "closed by the peer"
        except OSError as e:
            self.err = e.strerror
        self.c.close()
        self.done.set()

    def aborted(self, timeout=10):
        return self.done.wait(timeout) and self.err == "Software caused connection abort"


def foreign_listener(port):
    """Another program listening on port."""
    p = subprocess.Popen([sys.executable, "-c", f"""
import socket, time
s = socket.create_server(("", {port}), family=socket.AF_INET6, dualstack_ipv6=True)
print("ready", flush=True)
while True:
    s.accept()[0].close()
"""], stdout=subprocess.PIPE, text=True)
    procs.append(p)
    p.stdout.readline()
    return p


def main():
    panel = start_panel()
    check("panel up on 2053", until(lambda: answers(2053), 30))
    check("login", login(2053))
    inbound = {
        "remark": "pp", "enable": "true", "listen": "", "port": 20001, "protocol": "vless",
        "expiryTime": 0, "trafficReset": "never", "xrayInstance": "", "xrayCores": 0,
        "settings": '{"clients":[{"id":"6a3d2d8c-5f8e-4f11-9a51-1d9b3c7e2a10","email":"pp","enable":true}],"decryption":"none"}',
        "streamSettings": '{"network":"tcp","security":"none"}',
        "sniffing": '{"enabled":false}',
    }
    res = api(2053, "/panel/api/inbounds/add", data=inbound)
    check("inbound added", res.get("success"), res.get("msg"))
    check("a core runs", until(lambda: len(cores(panel)) > 0, 30))
    pid = panel.pid

    # 1. Through the API.
    h = Holder(P1)
    check("1: the outgoing connection holds the port", not can_bind(P1))
    settings = api(2053, "/panel/setting/all")["obj"]
    settings["webPort"] = P1
    res = api(2053, "/panel/setting/update", json=settings)
    check("1: the API accepts the port", res.get("success"), res.get("msg"))
    check("1: the save closed the connection", h.aborted(), h.err)
    r = reserved()
    check("1: the new port is reserved, the old one still is", P1 in r and 2053 in r, sorted(r))
    late = Holder(P1)  # a bound socket ignores the reservation
    check("1: a connection bound after the save holds it", not can_bind(P1))
    panel.send_signal(signal.SIGHUP)
    check("1: the panel comes up on the new port", until(lambda: answers(P1), 30))
    check("1: the restart closed the late connection", late.aborted(), late.err)
    check("1: x-ui never exited", panel.poll() is None and panel.pid == pid)
    check("1: the old port is free", not answers(2053))
    check("1: cores run", until(lambda: len(cores(panel)) > 0, 30))
    check("1: login on the new port", login(P1))

    # 2. Through "x-ui setting -port".
    h = Holder(P2)
    check("2: the outgoing connection holds the port", not can_bind(P2))
    out = subprocess.run([PANEL, "setting", "-port", str(P2)], cwd=T, capture_output=True, text=True)
    check("2: the CLI sets the port", out.returncode == 0, out.stdout + out.stderr)
    check("2: the CLI closed the connection", h.aborted(), h.err)
    check("2: the new port is reserved", P2 in reserved(), sorted(reserved()))
    panel.send_signal(signal.SIGHUP)
    check("2: the panel comes up on the new port", until(lambda: answers(P2), 30))
    check("2: x-ui never exited", panel.poll() is None and panel.pid == pid)
    check("2: cores run", until(lambda: len(cores(panel)) > 0, 30))
    check("2: login on the new port", login(P2))

    # 3. Another program listens on the new port.
    other = foreign_listener(P3)
    settings = api(P2, "/panel/setting/all")["obj"]
    settings["webPort"] = P3
    res = api(P2, "/panel/setting/update", json=settings)
    msg = res.get("msg", "")
    check("3: the API refuses it, naming the program", not res.get("success") and "listens on it" in msg and "python3" in msg, msg)
    check("3: the refused port is not reserved", P3 not in reserved(), sorted(reserved()))
    out = subprocess.run([PANEL, "setting", "-port", str(P3)], cwd=T, capture_output=True, text=True)
    check("3: the CLI refuses it", out.returncode != 0 and "listens on it" in out.stdout, out.stdout)
    set_db("webPort", P3)
    before = cores(panel)
    panel.send_signal(signal.SIGHUP)
    check("3: the restart is refused", until(lambda: f"Not restarting the servers: Web port {P3} is in use" in log_text(), 30))
    time.sleep(2)
    check("3: the panel stays on its port", answers(P2))
    check("3: x-ui never exited", panel.poll() is None and panel.pid == pid)
    check("3: the cores were not touched", before and cores(panel) == before, f"{before} -> {cores(panel)}")
    settings = api(P2, "/panel/setting/all")["obj"]
    settings["webPort"] = P2
    res = api(P2, "/panel/setting/update", json=settings)
    check("3: the port the panel listens on is accepted back", res.get("success"), res.get("msg"))

    # 4. An address the host does not have, on the same port.
    settings = api(P2, "/panel/setting/all")["obj"]
    settings["webListen"] = "203.0.113.9"
    res = api(P2, "/panel/setting/update", json=settings)
    msg = res.get("msg", "")
    check("4: the API refuses it", not res.get("success") and "cannot be used" in msg, msg)
    out = subprocess.run([PANEL, "setting", "-listenIP", "203.0.113.9"], cwd=T, capture_output=True, text=True)
    check("4: the CLI refuses it", out.returncode != 0 and "cannot be used" in out.stdout, out.stdout)
    set_db("webListen", "203.0.113.9")
    before = cores(panel)
    panel.send_signal(signal.SIGHUP)
    check("4: the restart is refused", until(lambda: "Not restarting the servers: Web address 203.0.113.9 cannot be used" in log_text(), 30))
    time.sleep(2)
    check("4: the panel stays on its port", answers(P2))
    check("4: x-ui never exited", panel.poll() is None and panel.pid == pid)
    check("4: the cores were not touched", before and cores(panel) == before, f"{before} -> {cores(panel)}")
    set_db("webListen", "")
    set_db("webPort", P3)

    # 5. x-ui starts while another program listens on its port.
    stop_panel(panel)
    panel = start_panel()
    time.sleep(5)
    check("5: x-ui stays up", panel.poll() is None)
    check("5: its cores run", until(lambda: len(cores(panel)) > 0, 30))
    check("5: the web server is not up", not answers(P3))
    check("5: it says why and that it retries", "cannot listen on :43003" in log_text() and "retrying every 10s" in log_text())
    other.kill()
    other.wait()
    check("5: the panel listens once the port is free", until(lambda: answers(P3), 30))
    check("5: x-ui stayed up throughout", panel.poll() is None)

    # 6. x-ui starts while an outgoing connection has its port.
    stop_panel(panel)
    h = Holder(P3)
    check("6: the outgoing connection holds the port", not can_bind(P3))
    started = time.time()
    panel = start_panel()
    check("6: the panel listens at once", until(lambda: answers(P3), 15), f"{time.time() - started:.1f}s")
    check("6: the connection was closed", h.aborted(), h.err)
    check("6: cores run", until(lambda: len(cores(panel)) > 0, 30))
    stop_panel(panel)
    check("6: x-ui stops cleanly", panel.returncode == 0, panel.returncode)


try:
    main()
finally:
    for p in procs:
        if p.poll() is None:
            p.kill()
            p.wait()
    failed = [n for n, ok in results if not ok]
    print(f"\n{len(results) - len(failed)}/{len(results)} passed")
    if failed:
        print("panel logs:", LOG, os.path.join(T, "log", "3xui.log"))
        for line in log_text().splitlines()[-40:]:
            print("  " + line)
        sys.exit(1)
