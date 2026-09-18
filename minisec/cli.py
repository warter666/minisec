"""Single CLI entry for minisec's two tools.

    python -m minisec.cli scan --host 127.0.0.1 --ports 1-1024 --banner
    python -m minisec.cli fuzz --target ./parser --seed seed.bin --iters 500
"""

import argparse
import sys

from . import fuzz as _fuzz
from . import portscan as _portscan


def cmd_scan(args):
    results = _portscan.scan(args.host, args.ports, timeout=args.timeout,
                             banner=args.banner,
                             allow_external=args.allow_external)
    if not results:
        print("no open ports found")
        return 1
    for r in results:
        line = f"{r['host']}:{r['port']} open"
        if r["banner"]:
            line += f"  banner: {r['banner'][:60]}"
        print(line)
    return 0


def cmd_fuzz(args):
    f = _fuzz.Fuzzer(args.target, args.seed, out_dir=args.out,
                     timeout=args.timeout, max_iters=args.iters,
                     stop_on_crashes=args.stop_on_crashes,
                     seed=args.seed_rng, tokens=args.token or [])
    crashes = f.run()
    print(f"{f.iters} iterations, {len(crashes)} crash(es)")
    for c in crashes:
        print(f"  saved: {c}")
    return 0 if crashes else 1


def main(argv=None):
    p = argparse.ArgumentParser(
        prog="minisec",
        description="Educational security tools (scanner + fuzzer)")
    sub = p.add_subparsers(dest="cmd", required=True)

    ps = sub.add_parser("scan", help="TCP connect scan (private/loopback only)")
    ps.add_argument("--host", action="append", required=True,
                    help="target host/IP; repeatable")
    ps.add_argument("--ports", default="1-1024",
                    help="80 | 1-1024 | 80,443,8000-8100")
    ps.add_argument("--timeout", type=float, default=1.0)
    ps.add_argument("--banner", action="store_true")
    ps.add_argument("--allow-external", action="store_true",
                    help="permit public addresses (only with authorization)")
    ps.set_defaults(func=cmd_scan)

    fz = sub.add_parser("fuzz", help="mutation fuzzer for file-input commands")
    fz.add_argument("--target", nargs="+", required=True,
                    help="target command, e.g. -- ./parser")
    fz.add_argument("--seed", action="append", required=True,
                    help="seed input file; repeatable")
    fz.add_argument("--iters", type=int, default=2000)
    fz.add_argument("--out", default="crashes")
    fz.add_argument("--timeout", type=float, default=2.0)
    fz.add_argument("--stop-on-crashes", type=int, default=1)
    fz.add_argument("--seed-rng", type=int, default=None,
                    help="PRNG seed for reproducible runs")
    fz.add_argument("--token", action="append",
                    help="dictionary token to inject; repeatable")
    fz.set_defaults(func=cmd_fuzz)

    args = p.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
