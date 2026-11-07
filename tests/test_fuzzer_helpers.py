"""Unit tests for fuzzer helper functions."""

import unittest
from fuzzing.fuzzer import (
    classify_payload,
    ensure_url,
    extract_parameters,
    build_param_url,
    body_similarity_ratio,
)


class TestFuzzerHelpers(unittest.TestCase):
    def test_classify_payload(self):
        self.assertEqual(classify_payload("' OR 1=1--"), "sqli")
        self.assertEqual(classify_payload("<script>alert(1)</script>"), "xss")
        self.assertEqual(classify_payload("../../etc/passwd"), "lfi")
        self.assertEqual(classify_payload("{{7*7}}"), "ssti")
        self.assertEqual(classify_payload("normal_text"), "unknown")

    def test_ensure_url(self):
        url = ensure_url("http://example.com/search")
        self.assertIn("fuzz=FUZZ", url)
        url_with_query = ensure_url("http://example.com/search?q=test")
        self.assertEqual(url_with_query, "http://example.com/search?q=test")

    def test_extract_parameters(self):
        params = extract_parameters("http://example.com/search?q=apple&category=fruit")
        self.assertEqual(params, {"q": "apple", "category": "fruit"})

    def test_build_param_url(self):
        url = "http://example.com/search?q=test&page=1"
        res = build_param_url(url, "q", "' OR 1=1--", url_encode=True)
        self.assertIn("page=1", res)
        self.assertTrue("%27" in res or "%20" in res)

    def test_body_similarity_ratio(self):
        self.assertEqual(body_similarity_ratio("hello world", "hello world"), 1.0)
        ratio = body_similarity_ratio("hello world", "goodbye world")
        self.assertTrue(0.0 < ratio < 1.0)


if __name__ == "__main__":
    unittest.main()
