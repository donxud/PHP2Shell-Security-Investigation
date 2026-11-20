"""Run with: python3 -m unittest test_triage.py"""

import unittest

from triage import (
    EOL,
    OK,
    REVIEW_BACKPORT,
    REVIEW_BRANCH,
    REVIEW_SOURCE,
    REVIEW_VERSION,
    UPDATE,
    classify,
)


class ClassifyTests(unittest.TestCase):
    def test_below_fix_needs_update(self):
        self.assertEqual(classify("8.4.26", "upstream"), UPDATE)
        self.assertEqual(classify("8.2.0", "upstream"), UPDATE)

    def test_at_or_above_fix(self):
        for v in ("8.2.36", "8.3.37", "8.4.28", "8.5.13", "8.5.14", "8.6.0", "8.4.28-1"):
            self.assertEqual(classify(v, "upstream"), OK, v)

    def test_october_php2shell_releases_still_need_the_november_update(self):
        for v in ("8.2.35", "8.3.36", "8.4.27", "8.5.12"):
            self.assertEqual(classify(v, "upstream"), UPDATE, v)

    def test_prereleases_and_unrecognized_builds_need_review(self):
        for v in ("8.6.0RC7", "8.6.0-dev", "8.5.13beta1", "8.4.28-custom"):
            self.assertEqual(classify(v, "upstream"), REVIEW_VERSION, v)

    def test_eol_branches(self):
        for v in ("7.4.33", "8.0.30", "8.1.31"):
            self.assertEqual(classify(v, "upstream"), EOL, v)

    def test_backport_sources_need_review(self):
        self.assertEqual(classify("8.2.34", "vendor-backport"), REVIEW_BACKPORT)
        self.assertEqual(classify("8.4.27-1~deb13u1", "distro"), REVIEW_BACKPORT)

    def test_bad_or_unknown_versions(self):
        self.assertEqual(classify("", "upstream"), REVIEW_VERSION)
        self.assertEqual(classify(None, "upstream"), REVIEW_VERSION)
        self.assertEqual(classify("8.4", "upstream"), REVIEW_VERSION)
        self.assertEqual(classify("7.3.33", "upstream"), REVIEW_BRANCH)

    def test_eol_vendor_backport(self):
        self.assertEqual(classify("8.1.31", "vendor-backport"), REVIEW_BACKPORT)
        self.assertEqual(classify("8.0.30", "distro"), REVIEW_BACKPORT)

    def test_unknown_source_needs_review(self):
        self.assertEqual(classify("8.4.27", "unknown"), REVIEW_SOURCE)
        self.assertEqual(classify("8.4.27", ""), REVIEW_SOURCE)


if __name__ == "__main__":
    unittest.main()
