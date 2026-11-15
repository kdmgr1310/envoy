#!/usr/bin/env python3
"""Guard the certifi and hickory-net pins against regressing below the fixed versions.

The advisory fixes referenced by this guard are GHSA-6q48-6c7w-9gw2 /
PYSEC-2026-4320 (certifi) and RUSTSEC-2026-0509 (hickory-net).  Every pinned
copy of either package in the repository must be at or above the fixed version
so that no vulnerable artifact can be resolved.

The test only reads dependency manifests/lockfiles that already exist, so it
can run before the pins are updated (where it fails) and afterwards (where it
passes).
"""

import pathlib
import re
import unittest

REPO_ROOT = pathlib.Path(__file__).resolve().parents[2]

# Fixed versions from the runtime evidence.
CERTIFI_FIXED = (2026, 10, 18)
CERTIFI_FIXED_CHECKSUMS = {
    "73191c47aaa79da394e8fee2dbc2ec827432cab56311122c9e47abf79e390f62",
    "b9995d97b64d0431a5af837d8ca8cd6238104d1f319f04bd93ea43124d6c861e",
}
HICKORY_NET_FIXED = (0, 26, 2)
HICKORY_NET_FIXED_SHA256 = "084e7bd6a377435d568f652153e571b50970d7ccc1d1eeec0519f834632287e1"
HICKORY_NET_VULNERABLE_SHA256 = "e2295ed2f9c31e471e1428a8f88a3f0e1f4b27c15049592138d1eebe9c35b183"

CARGO_LOCKS = [
    "Cargo.lock",
    "Cargo.Bazel.lock",
    "Cargo.Bazel.envoy.lock",
    "Cargo.Bazel.dynamic_modules.lock",
    "bazel/tests/external/Cargo.Bazel.lock",
    "docs/Cargo.Bazel.lock",
]

REQUIREMENT_LINE = re.compile(r"^[A-Za-z0-9._-]+==", re.MULTILINE)


def _version_tuple(version: str) -> tuple:
    return tuple(int(part) for part in version.split("."))


def _fixed() -> str:
    return ".".join(str(part) for part in CERTIFI_FIXED)


class CertifiPinsTest(unittest.TestCase):
    def test_no_requirements_file_pins_certifi_below_fixed_version(self):
        seen = 0
        for requirements in REPO_ROOT.glob("**/requirements.txt"):
            if ".git" in requirements.parts:
                continue
            text = requirements.read_text()
            for match in re.finditer(r"^certifi==([0-9.]+) \\$", text, re.MULTILINE):
                seen += 1
                pinned = match.group(1)
                self.assertGreaterEqual(
                    _version_tuple(pinned),
                    CERTIFI_FIXED,
                    f"{requirements.relative_to(REPO_ROOT)} pins certifi {pinned}, "
                    f"which is below the fixed {_fixed()}",
                )
                next_requirement = REQUIREMENT_LINE.search(text, match.end())
                block_end = next_requirement.start() if next_requirement else len(text)
                block = text[match.start() : block_end]
                hashes = set(re.findall(r"--hash=sha256:([0-9a-f]{64})", block))
                self.assertTrue(
                    hashes and hashes <= CERTIFI_FIXED_CHECKSUMS,
                    f"{requirements.relative_to(REPO_ROOT)} carries hashes that do not "
                    f"belong to certifi {_fixed()}",
                )
        self.assertGreater(seen, 0, "expected at least one pinned certifi artifact")


class HickoryNetPinsTest(unittest.TestCase):
    def test_no_cargo_lock_records_hickory_net_below_fixed_version(self):
        seen = 0
        for lock_name in CARGO_LOCKS:
            lock = REPO_ROOT / lock_name
            if not lock.exists():
                continue
            text = lock.read_text()
            for match in re.finditer(r'name = "hickory-net"\nversion = "([0-9.]+)"', text):
                seen += 1
                self.assertGreaterEqual(
                    _version_tuple(match.group(1)),
                    HICKORY_NET_FIXED,
                    f"{lock_name} locks hickory-net {match.group(1)}, below the fixed "
                    f"{'.'.join(map(str, HICKORY_NET_FIXED))}",
                )
            for match in re.finditer(r'"hickory-net ([0-9.]+)": \{', text):
                seen += 1
                self.assertGreaterEqual(
                    _version_tuple(match.group(1)),
                    HICKORY_NET_FIXED,
                    f"{lock_name} vendors hickory-net {match.group(1)}, below the fixed "
                    f"{'.'.join(map(str, HICKORY_NET_FIXED))}",
                )
            for match in re.finditer(r'"hickory-net/([0-9.]+)/download"', text):
                self.assertGreaterEqual(
                    _version_tuple(match.group(1)),
                    HICKORY_NET_FIXED,
                    f"{lock_name} still downloads hickory-net {match.group(1)}",
                )
        self.assertGreater(seen, 0, "expected at least one locked hickory-net entry")

    def test_cargo_locks_record_the_fixed_hickory_net_checksum(self):
        for lock_name in CARGO_LOCKS:
            lock = REPO_ROOT / lock_name
            if not lock.exists() or "hickory-net" not in lock.read_text():
                continue
            text = lock.read_text()
            self.assertTrue(
                HICKORY_NET_FIXED_SHA256 in text,
                f"{lock_name} does not record the crates.io checksum of the fixed hickory-net",
            )
            self.assertFalse(
                HICKORY_NET_VULNERABLE_SHA256 in text,
                f"{lock_name} still records the checksum of the vulnerable hickory-net",
            )


if __name__ == "__main__":
    unittest.main()
