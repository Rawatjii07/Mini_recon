"""Unit tests for ScopeChecker utility."""

import unittest
from utils.scope_checker import ScopeChecker, ScopeError


class TestScopeChecker(unittest.TestCase):
    def test_scope_checker_allows_exact_domain(self):
        checker = ScopeChecker.from_csv("example.com")
        self.assertIsNotNone(checker)
        self.assertTrue(checker.is_in_scope("example.com"))
        self.assertTrue(checker.is_in_scope("https://example.com/login"))

    def test_scope_checker_allows_subdomains(self):
        checker = ScopeChecker.from_csv("example.com")
        self.assertIsNotNone(checker)
        self.assertTrue(checker.is_in_scope("api.example.com"))
        self.assertTrue(checker.is_in_scope("https://dev.api.example.com/v1/test"))

    def test_scope_checker_blocks_out_of_scope(self):
        checker = ScopeChecker.from_csv("example.com")
        self.assertIsNotNone(checker)
        self.assertFalse(checker.is_in_scope("notexample.com"))
        self.assertFalse(checker.is_in_scope("evil.com"))
        with self.assertRaises(ScopeError):
            checker.require_in_scope("https://evil.com", "test")

    def test_scope_checker_empty_csv(self):
        checker = ScopeChecker.from_csv("")
        self.assertIsNone(checker)


if __name__ == "__main__":
    unittest.main()
