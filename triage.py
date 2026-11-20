#!/usr/bin/env python3
"""Offline PHP2Shell and phpAfterShell patch-baseline triage.

Reads a CSV inventory and compares each PHP version string with the fixed
upstream releases published on 19 Nov 2026 for the advisories in the README. It makes no network requests,
sends no payloads and does not test exploitability. The result is a first
triage hint, not proof of vulnerability, of a working patch, or of a clean host.

CSV columns: asset, php_version, exposure, package_source
  exposure:       internet | internal | (anything else is treated as unknown)
  package_source: upstream | distro | vendor-backport | unknown

Exit codes: 0 = nothing needs action, 1 = at least one asset needs action or
review, 2 = input error. This lets the script gate a CI job or a scheduled check.
"""

import argparse
import csv
import re
import sys

# Stable upstream release baselines for the advisories in the README.
FIXED = {
    (8, 2): (8, 2, 36),
    (8, 3): (8, 3, 37),
    (8, 4): (8, 4, 28),
    (8, 5): (8, 5, 13),
    (8, 6): (8, 6, 0),
}

# Legacy branches that should move to a supported upstream release.
EOL_AFFECTED = {(7, 4), (8, 0), (8, 1)}

EXPOSURE_RANK = {"internet": 0, "internal": 1}

# Leading major.minor.patch; tolerates distro suffixes such as 8.4.27-1~deb13u1.
VERSION_RE = re.compile(r"^\s*(\d+)\.(\d+)\.(\d+)")
STABLE_UPSTREAM_RE = re.compile(r"\d+\.\d+\.\d+(?:-\d+)?")

UPDATE = "UPDATE"
EOL = "UPDATE: end-of-life branch, no upstream fix"
OK = "MEETS LISTED UPSTREAM BASELINE"
REVIEW_BACKPORT = "MANUAL REVIEW: verify distro/vendor package advisory"
REVIEW_VERSION = "MANUAL REVIEW: missing/nonstandard version"
REVIEW_BRANCH = "MANUAL REVIEW: branch not covered by advisory"
REVIEW_SOURCE = "MANUAL REVIEW: unknown package source"

NEEDS_ACTION = {
    UPDATE, EOL, REVIEW_BACKPORT, REVIEW_VERSION, REVIEW_BRANCH, REVIEW_SOURCE,
}


def classify(raw_version, source):
    """Return a conservative triage label for one asset."""
    match = VERSION_RE.match(raw_version or "")
    if not match:
        return REVIEW_VERSION

    parts = tuple(int(x) for x in match.groups())
    branch = parts[:2]
    source = (source or "").strip().lower()

    # Vendor and distro builds may contain backported security
    # fixes, including on end-of-life upstream branches.
    # A version string alone cannot prove their patch status.
    if source in ("distro", "vendor-backport"):
        return REVIEW_BACKPORT

    if branch in EOL_AFFECTED:
        return EOL

    threshold = FIXED.get(branch)
    if threshold is None:
        return REVIEW_BRANCH

    # Unknown sources must not be treated as upstream.
    if source != "upstream":
        return REVIEW_SOURCE

    # Release candidates, development builds, and unrecognized suffixes need review.
    # PHP also publishes numbered upstream rebuilds such as the Windows -1 builds.
    if not STABLE_UPSTREAM_RE.fullmatch(raw_version.strip()):
        return REVIEW_VERSION

    return UPDATE if parts < threshold else OK


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("csv_path", nargs="?", default="assets.csv")
    args = parser.parse_args(argv)

    try:
        with open(args.csv_path, newline="", encoding="utf-8") as f:
            rows = list(csv.DictReader(f))
    except OSError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    required = {"asset", "php_version", "exposure", "package_source"}
    if rows and not required.issubset(rows[0].keys()):
        print(f"error: CSV must have columns {sorted(required)}", file=sys.stderr)
        return 2

    results = [
        (row, classify(row["php_version"], row["package_source"])) for row in rows
    ]
    # Internet-facing assets first, then internal, then unknown exposure.
    results.sort(
        key=lambda r: EXPOSURE_RANK.get(r[0]["exposure"].strip().lower(), 2)
    )

    for row, label in results:
        exposure = row["exposure"].strip() or "unknown"
        print(f"[{exposure:<8}] {row['asset']}: {label}")

    return 1 if any(label in NEEDS_ACTION for _, label in results) else 0


if __name__ == "__main__":
    sys.exit(main())
