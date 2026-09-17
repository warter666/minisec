"""Educational TCP connect scanner (naabu-inspired, stdlib only).

Restricted to loopback/private targets unless allow_external is set — this is
a learning tool, not a network mapper.
"""

import concurrent.futures
import ipaddress
import socket

DEFAULT_TIMEOUT = 1.0


def _check_target_allowed(target: str, allow_external: bool):
    """Resolve and require loopback/private unless the caller opts out."""
    infos = socket.getaddrinfo(target, None, proto=socket.IPPROTO_TCP)
    for info in infos:
        ip = ipaddress.ip_address(info[4][0])
        if allow_external or ip.is_private or ip.is_loopback:
            return
    raise ValueError(
        f"{target} resolves to a public address; pass allow_external=True "
        "only if you are authorized to test it")


def parse_ports(spec: str) -> list:
    """'80' / '1-1024' / '80,443,8000-8100' -> sorted unique list."""
    out = set()
    for part in spec.split(","):
        if "-" in part:
            lo, hi = part.split("-", 1)
            out.update(range(int(lo), int(hi) + 1))
        else:
            out.add(int(part))
    return sorted(p for p in out if 1 <= p <= 65535)


def _grab_banner(sock):
    try:
        sock.settimeout(0.5)
        data = sock.recv(128)
        return data.decode("utf-8", "replace").strip()
    except OSError:
        return ""


def _probe(host, port, timeout, banner):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.settimeout(timeout)
        if s.connect_ex((host, port)) != 0:
            return None
        b = _grab_banner(s) if banner else ""
        return {"host": host, "port": port, "banner": b}


def scan(targets, ports, timeout=DEFAULT_TIMEOUT, banner=False,
         max_workers=256, allow_external=False):
    """Scan an iterable of hosts over a port list; returns sorted open-port dicts."""
    if isinstance(ports, str):
        ports = parse_ports(ports)
    hosts = []
    for t in targets:
        _check_target_allowed(t, allow_external)
        infos = socket.getaddrinfo(t, None, proto=socket.IPPROTO_TCP)
        addr = infos[0][4][0]
        if isinstance(ipaddress.ip_address(addr), ipaddress.IPv6Address):
            raise ValueError("IPv6 targets not supported by this toy scanner")
        hosts.append(addr)

    results = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as ex:
        futs = [ex.submit(_probe, h, p, timeout, banner) for h in hosts for p in ports]
        for f in concurrent.futures.as_completed(futs):
            r = f.result()
            if r:
                results.append(r)
    return sorted(results, key=lambda r: (r["host"], r["port"]))
