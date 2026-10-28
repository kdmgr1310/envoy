#!/usr/bin/env python3
"""Guard the CVE-fixed pins for requests, setuptools, and tokio.

These packages were bumped to the fixed versions named in the runtime CVE
evidence (GHSA advisory identifiers).  Each assertion exercises only existing
manifest files (no new source code), so this test fails on the pre-fix pins
and passes after the pins are updated.
"""

import pathlib
import re
import unittest

REPO_ROOT = pathlib.Path(__file__).resolve().parents[2]

# Fixed versions from the CVE evidence (package -> fixed version).
PYTHON_FIXED = {
    "requests": "2.20.0",
    "setuptools": "0.7",
}

# Compiled Python requirements files that must pin the fixed versions.
PYTHON_REQUIREMENTS = {
    "docs/tools/python/requirements.txt": ["requests"],
    "mobile/tools/python/requirements.txt": ["requests"],
    "tools/base/requirements.txt": ["requests", "setuptools"],
}

# Rust manifests (path -> (dependency name, fixed version)).
CARGO_MANIFESTS = {
    "source/extensions/dynamic_modules/builtin_extensions/Cargo.toml": (
        "tokio",
        "1.8.4",
    ),
}

PYTHON_PIN_RE = re.compile(r"^([A-Za-z0-9_.-]+)(?:\[[^\]]*\])?==([0-9][^ \\]*)")


def _python_pins(rel_path):
    """Return {package: version} for every pinned line in a requirements file."""
    pins = {}
    text = (REPO_ROOT / rel_path).read_text(encoding="utf-8")
    for line in text.splitlines():
        match = PYTHON_PIN_RE.match(line)
        if match:
            pins[match.group(1)] = match.group(2)
    return pins


def _cargo_manifest_versions(rel_path):
    """Return {dependency: version} for a Cargo.toml manifest."""
    versions = {}
    text = (REPO_ROOT / rel_path).read_text(encoding="utf-8")
    for line in text.splitlines():
        match = re.match(
            r'^([a-z0-9_-]+)\s*=\s*\{\s*version\s*=\s*"([0-9][^"]*)"',
            line,
        )
        if match:
            versions[match.group(1)] = match.group(2)
    return versions


class DependencyPinsTest(unittest.TestCase):
    """Every tracked manifest must pin the CVE-fixed version."""

    def test_python_requirements_pin_fixed_versions(self):
        failures = []
        for rel_path, packages in PYTHON_REQUIREMENTS.items():
            pins = _python_pins(rel_path)
            for pkg in packages:
                pinned = pins.get(pkg)
                fixed = PYTHON_FIXED[pkg]
                if pinned != fixed:
                    failures.append(
                        "%s: %s==%r (expected %s)"
                        % (rel_path, pkg, pinned, fixed)
                    )
        self.assertEqual(failures, [], "\n".join(failures))

    def test_cargo_manifests_pin_fixed_versions(self):
        failures = []
        for rel_path, (dep, fixed) in CARGO_MANIFESTS.items():
            versions = _cargo_manifest_versions(rel_path)
            if versions.get(dep) != fixed:
                failures.append(
                    "%s: %s=%r (expected %s)"
                    % (rel_path, dep, versions.get(dep), fixed)
                )
        self.assertEqual(failures, [], "\n".join(failures))


if __name__ == "__main__":
    unittest.main()
