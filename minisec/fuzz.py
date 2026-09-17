"""Mutation-based black-box file fuzzer (litefuzz-inspired, stdlib only).

Runs a command-line target on mutated seed inputs; a run is a "crash" when the
process exits non-zero, times out, or is killed by a signal. Crashing inputs are
deduplicated by their mutation recipe and saved under an output directory.

Educational tool: understand mutation strategies and harnessing.
"""

import hashlib
import random
import shutil
import subprocess
from pathlib import Path

# random.Random (not secrets) is deliberate: fuzzing needs a seedable,
# reproducible PRNG for experiment reruns, not cryptographic randomness.
BOUNDARY_BYTES = [0x00, 0x01, 0x7F, 0x80, 0xFE, 0xFF]
MAGIC_LENGTHS = [b"%s", b"%n", b"AAAA"]


def bit_flip(data: bytes, rng) -> bytes:
    b = bytearray(data)
    if not b:
        return bytes(b)
    for _ in range(rng.randint(1, 4)):
        i = rng.randrange(len(b))
        b[i] ^= 1 << rng.randrange(8)
    return bytes(b)


def byte_random(data: bytes, rng) -> bytes:
    b = bytearray(data)
    if not b:
        return bytes(b)
    for _ in range(rng.randint(1, 8)):
        b[rng.randrange(len(b))] = rng.randrange(256)
    return bytes(b)


def boundary_inject(data: bytes, rng) -> bytes:
    b = bytearray(data)
    if not b:
        return bytes(BOUNDARY_BYTES)
    i = rng.randrange(len(b))
    chunk = bytes([rng.choice(BOUNDARY_BYTES) for _ in range(rng.randint(1, 4))])
    return bytes(b[:i] + chunk + b[i:])


def block_delete(data: bytes, rng) -> bytes:
    if len(data) < 4:
        return data
    i = rng.randrange(len(data) - 1)
    j = min(len(data), i + rng.randint(1, max(1, len(data) // 4)))
    return data[:i] + data[j:]


def block_duplicate(data: bytes, rng) -> bytes:
    if not data:
        return data
    i = rng.randrange(len(data))
    j = min(len(data), i + rng.randint(1, max(1, len(data) // 4)))
    return data[:j] + data[i:j] + data[j:]


def splice(a: bytes, b: bytes, rng) -> bytes:
    if not a:
        return b
    if not b:
        return a
    i = rng.randrange(len(a) + 1)
    j = rng.randrange(len(b) + 1)
    return a[:i] + b[j:]


def token_inject(data: bytes, rng, tokens=()):
    if not tokens:
        return data
    tok = rng.choice(list(tokens))
    i = rng.randrange(len(data) + 1) if data else 0
    return data[:i] + tok + data[i:]


MUTATORS = [bit_flip, byte_random, boundary_inject, block_delete, block_duplicate]


class Fuzzer:
    def __init__(self, target_cmd, seeds, out_dir="crashes", timeout=2.0,
                 max_iters=2000, stop_on_crashes=1, seed=None, tokens=()):
        """tokens: dictionary of magic bytes the target is likely to check for
        (AFL-style dict). Blind mutation cannot synthesize long magic tokens,
        which is exactly why real fuzzers ship dictionaries."""
        self.target_cmd = list(target_cmd)
        self.seeds = [Path(s).read_bytes() for s in seeds]
        self.tokens = [t if isinstance(t, bytes) else t.encode() for t in tokens]
        self.out_dir = Path(out_dir)
        self.timeout = timeout
        self.max_iters = max_iters
        self.stop_on_crashes = stop_on_crashes
        self.rng = random.Random(seed)
        self.crashes = []
        self.iters = 0

    def _run(self, data: bytes):
        """True when the target crashed on this input."""
        try:
            p = subprocess.run(self.target_cmd, input=data,
                               stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                               timeout=self.timeout)
        except subprocess.TimeoutExpired:
            return True
        return p.returncode != 0

    def _mutate(self):
        data = self.rng.choice(self.seeds)
        if len(self.seeds) > 1 and self.rng.random() < 0.15:
            data = splice(data, self.rng.choice(self.seeds), self.rng)
        for m in MUTATORS:
            if self.rng.random() < 0.3:
                data = m(data, self.rng)
        if self.tokens and self.rng.random() < 0.25:
            data = token_inject(data, self.rng, self.tokens)
        if self.rng.random() < 0.1:
            data += bytes(MAGIC_LENGTHS[self.rng.randrange(len(MAGIC_LENGTHS))])
        return data

    def _save_crash(self, data: bytes):
        digest = hashlib.sha256(data).hexdigest()[:16]
        self.out_dir.mkdir(parents=True, exist_ok=True)
        path = self.out_dir / f"crash_{digest}.bin"
        if not path.exists():
            path.write_bytes(data)
        self.crashes.append(path)
        return path

    def run(self):
        while self.iters < self.max_iters and \
                len(self.crashes) < self.stop_on_crashes:
            data = self._mutate()
            self.iters += 1
            if self._run(data):
                self._save_crash(data)
        return self.crashes
