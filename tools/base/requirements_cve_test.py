#!/usr/bin/env python3
"""Guard the CVE-fixed dependency pins across Envoy's dependency manifests.

The pins asserted here were bumped to the fixed versions named in the runtime
CVE evidence (PYSEC / GHSA / RUSTSEC advisory identifiers).  If a manifest
regresses below a fixed pin this test fails, and once the pins are updated it
passes.  Each assertion exercises only existing files (no new source code).
"""

import pathlib
import re
import unittest

REPO_ROOT = pathlib.Path(__file__).resolve().parents[2]

# Fixed versions from the CVE evidence (package -> fixed version).
PYTHON_FIXED = {
    "aiohttp": "3.13.4",
    "anyio": "4.14.2",
    "babel": "2.9.1",
    "black": "26.3.0",
    "cryptography": "42.0.0",
    "gitpython": "3.1.32",
    "httpx": "0.23.0",
    "jinja2": "2.7.2",
    "orjson": "3.11.6",
    "pyjwt": "2.14.0",
    "pyopenssl": "0.13.1",
    "python-gnupg": "0.3.7",
    "pyyaml": "5.4",
    "urllib3": "1.23",
}

# Packages that must be pinned (with a fixed version) in each compiled Python
# requirements file.
PYTHON_REQUIREMENTS = {
    "docs/tools/python/requirements.txt": [
        "aiohttp",
        "babel",
        "cryptography",
        "jinja2",
        "orjson",
        "pyjwt",
        "python-gnupg",
        "pyyaml",
        "urllib3",
    ],
    "mobile/tools/python/requirements.txt": [
        "anyio",
        "black",
        "httpx",
        "urllib3",
    ],
    "tools/base/requirements.txt": [
        "aiohttp",
        "cryptography",
        "gitpython",
        "jinja2",
        "orjson",
        "pyjwt",
        "pyopenssl",
        "python-gnupg",
        "pyyaml",
        "urllib3",
    ],
}

# Rust manifests (path -> (dependency name, fixed version)).
CARGO_MANIFESTS = {
    "source/extensions/dynamic_modules/sdk/rust/Cargo.toml": (
        "smallvec",
        "0.6.14",
    ),
    "source/extensions/dynamic_modules/builtin_extensions/Cargo.toml": (
        "hickory-resolver",
        "0.26.2",
    ),
    "bazel/external/cargo/Cargo.toml": ("protobuf", "1.7.5"),
}

# Go test-data modules that require github.com/envoyproxy/envoy.
GO_MODULES = [
    "contrib/golang/router/cluster_specifier/test/test_data/simple/go.mod",
    "contrib/golang/upstreams/http/tcp/test/test_data/go.mod",
    "contrib/golang/filters/network/test/test_data/go.mod",
    "contrib/golang/filters/http/test/test_data/go.mod",
    "contrib/golang/filters/http/test/test_data/dummy/go.mod",
]

GO_ENVOY_FIXED = "1.37.1"

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
        match = re.match(r'^([a-z0-9_-]+)\s*=\s*"([0-9][^"]*)"', line)
        if match:
            versions[match.group(1)] = match.group(2)
            continue
        match = re.match(
            r'^([a-z0-9_-]+)\s*=\s*\{\s*version\s*=\s*"([0-9][^"]*)"',
            line,
        )
        if match:
            versions[match.group(1)] = match.group(2)
    return versions


def _go_envoy_version(rel_path):
    """Return the pinned github.com/envoyproxy/envoy version in a go.mod."""
    text = (REPO_ROOT / rel_path).read_text(encoding="utf-8")
    match = re.search(r"github\.com/envoyproxy/envoy v([0-9]+\.[0-9]+\.[0-9]+)", text)
    return match.group(1) if match else None


class RequirementsCvePinTest(unittest.TestCase):
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

    def test_go_modules_pin_fixed_envoy_version(self):
        failures = []
        for rel_path in GO_MODULES:
            version = _go_envoy_version(rel_path)
            if version != GO_ENVOY_FIXED:
                failures.append(
                    "%s: envoy v%r (expected v%s)"
                    % (rel_path, version, GO_ENVOY_FIXED)
                )
        self.assertEqual(failures, [], "\n".join(failures))


if __name__ == "__main__":
    unittest.main()
