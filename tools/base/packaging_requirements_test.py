"""Tests the ``packaging`` pin used by the Python tooling.

``tools/protoprint`` resolves ``packaging`` from the ``tools/base`` requirements
(``@base_pip3``). The 26.3 release changed ``Version`` so that non-string input
raises ``InvalidVersion`` instead of ``TypeError``. This test guards the pin so
that the dependency cannot be silently reverted to a version without that
behaviour.
"""
import pathlib
import unittest

from packaging import version as packaging_version

EXPECTED_VERSION = "26.3"
EXPECTED_HASHES = {
    "94edc256424af38762eb31306eed28beb9f0efc50a8837492c9d6fd6004aed79",
    "d7193f7c8e4e93f444fde0262bf90af30e16fa0ad0ad44cb553c87339b23cd1c",
}


def requirements_path():
    """Finds ``tools/base/requirements.txt`` relative to this test."""
    here = pathlib.Path(__file__).resolve()
    for parent in here.parents:
        candidate = parent / "tools" / "base" / "requirements.txt"
        if candidate.is_file():
            return candidate
    return here.parent / "requirements.txt"


def packaging_pin_lines():
    """Returns the ``packaging`` pin line and its ``--hash`` lines."""
    lines = requirements_path().read_text().splitlines()
    for index, line in enumerate(lines):
        if line.startswith("packaging=="):
            pin = [line]
            for following in lines[index + 1:]:
                if not following.lstrip().startswith("--hash="):
                    break
                pin.append(following)
            return pin
    return []


def packaging_hashes(pin):
    """Returns the sha256 digests declared for the ``packaging`` pin."""
    hashes = set()
    for line in pin:
        if "--hash=sha256:" in line:
            hashes.add(line.rsplit("sha256:", 1)[-1].rstrip(" \\"))
    return hashes


class PackagingRequirementsTest(unittest.TestCase):

    def test_pinned_to_release_with_invalid_version_for_non_strings(self):
        pin = packaging_pin_lines()
        self.assertTrue(pin, "packaging is not pinned in requirements.txt")
        pinned_version = pin[0].split("==", 1)[1].rstrip(" \\")
        self.assertEqual(pinned_version, EXPECTED_VERSION)

    def test_pin_carries_published_hashes(self):
        self.assertEqual(packaging_hashes(packaging_pin_lines()), EXPECTED_HASHES)

    def test_call_sites_can_parse_the_repo_api_version(self):
        # Both affected call sites build a Version from a string value.
        self.assertEqual(packaging_version.Version("3.0.0").base_version, "3.0.0")


if __name__ == "__main__":
    unittest.main()
