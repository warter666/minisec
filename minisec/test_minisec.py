"""Offline self-verification: scanner against local listeners, fuzzer against a
crashing toy parser. Loopback only."""

import socket
import subprocess
import sys
import tempfile
import textwrap
import threading
from pathlib import Path

from minisec.portscan import parse_ports, scan
from minisec.fuzz import Fuzzer, bit_flip, splice


def _listener(port, banner=None):
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("127.0.0.1", port))
    srv.listen(5)

    def serve():
        try:
            while True:
                conn, _ = srv.accept()
                if banner:
                    conn.sendall(banner)
                conn.close()
        except OSError:
            pass

    t = threading.Thread(target=serve, daemon=True)
    t.start()
    return srv


def test_parse_ports():
    assert parse_ports("80") == [80]
    assert parse_ports("10-12,80") == [10, 11, 12, 80]
    assert parse_ports("0,70000") == []  # out of range dropped


def test_scan_finds_local_listeners():
    with _listener(24501), _listener(24502, b"mini-ftp ready\n"), \
            _listener(24503):
        results = scan(["127.0.0.1"], "24500-24510", timeout=0.5, banner=True)
    found = {r["port"]: r for r in results}
    assert set(found) == {24501, 24502, 24503}, found
    assert found[24502]["banner"] == "mini-ftp ready"


def test_scan_closed_port_reports_nothing():
    # find a definitely-closed port: bind, get its port, close it
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    closed = s.getsockname()[1]
    s.close()
    assert scan(["127.0.0.1"], str(closed), timeout=0.5) == []


def test_scan_prefers_ipv4_when_dual_stack():
    """A host that resolves ::1 first must still be scanned via its A record
    (regression: getaddrinfo order made 'localhost' fail with an IPv6 error)."""
    from minisec import portscan

    def fake_getaddrinfo(host, *args, **kwargs):
        # ::1 listed first, 127.0.0.1 second — the order that broke scan()
        return [(socket.AF_INET6, socket.SOCK_STREAM, 6, "", ("::1", 0)),
                (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("127.0.0.1", 0))]

    orig = portscan.socket.getaddrinfo
    portscan.socket.getaddrinfo = fake_getaddrinfo
    try:
        # closed port -> empty result, but crucially no IPv6 rejection
        s = socket.socket()
        s.bind(("127.0.0.1", 0))
        closed = s.getsockname()[1]
        s.close()
        assert scan(["dualstack.example"], str(closed)) == []
    finally:
        portscan.socket.getaddrinfo = orig


def test_scan_rejects_public_target():
    # a real public unicast address (example.com); the guard must reject it
    # BEFORE any packet is sent, so this never actually contacts the host
    try:
        scan(["93.184.216.34"], "80")
        raise AssertionError("public target should have been rejected")
    except ValueError as e:
        assert "allow_external" in str(e)


CRASHER = textwrap.dedent("""
    import sys
    data = sys.stdin.buffer.read()
    if b\"CRASHTOKEN\" in data:
        sys.exit(42)          # simulated memory-corruption abort
    if data.count(b\"(\") > 2000:
        raise RecursionError  # simulated stack exhaustion
    sys.exit(0)
""")


def test_fuzzer_finds_crash():
    with tempfile.TemporaryDirectory() as td:
        target = Path(td) / "crasher.py"
        target.write_text(CRASHER)
        seed = Path(td) / "seed.bin"
        seed.write_bytes(b"hello world " * 8)

        fz = Fuzzer([sys.executable, str(target)], [seed],
                    out_dir=Path(td) / "crashes", timeout=2.0,
                    max_iters=4000, stop_on_crashes=1, seed=1234,
                    tokens=[b"CRASHTOKEN"])  # AFL-style dict: blind mutation
        # cannot synthesize a 10-byte magic token on its own
        crashes = fz.run()
        assert crashes, "fuzzer found no crash within budget"
        # the saved sample must actually crash the target when replayed
        data = crashes[0].read_bytes()
        p = subprocess.run([sys.executable, str(target)], input=data,
                           capture_output=True)
        assert p.returncode == 42, (p.returncode, data[:50])
        # mutations are reproducible for a given seed
        rng_a = __import__("random").Random(7)
        rng_b = __import__("random").Random(7)
        assert bit_flip(b"abcdef", rng_a) == bit_flip(b"abcdef", rng_b)
        assert splice(b"aaaa", b"bbbb", __import__("random").Random(1)) is not None


if __name__ == "__main__":
    test_parse_ports()
    print("port spec parsing passed")
    test_scan_finds_local_listeners()
    print("local listener scan passed")
    test_scan_closed_port_reports_nothing()
    print("closed-port non-report passed")
    test_scan_prefers_ipv4_when_dual_stack()
    print("dual-stack IPv4 preference passed")
    test_scan_rejects_public_target()
    print("private-target guard passed")
    test_fuzzer_finds_crash()
    print("fuzzer crash discovery + replay passed")
    print("all minisec tests passed")
