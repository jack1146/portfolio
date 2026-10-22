
import unittest

from url_analyzer import analyze_url


class TestURLAnalyzer(unittest.TestCase):

    def test_empty_input(self):
        result = analyze_url("")
        self.assertTrue(
            any("empty" in item.lower() for item in result)
        )

    def test_hostname_is_reported(self):
        result = analyze_url("https://example.com/login")
        self.assertIn("Hostname: example.com", result)

    def test_http_warning(self):
        result = analyze_url("http://example.com")
        self.assertTrue(
            any("HTTP" in item for item in result)
        )

    def test_ip_hostname(self):
        result = analyze_url("http://192.0.2.10/login")
        self.assertTrue(
            any("IP address" in item for item in result)
        )

    def test_at_symbol_warning(self):
        result = analyze_url(
            "https://example.com@fake-login.example.net/account"
        )
        self.assertTrue(
            any("'@'" in item for item in result)
        )


if __name__ == "__main__":
    unittest.main()
