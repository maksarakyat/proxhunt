import unittest

from proxhunt.store import compute_score
from proxhunt.util import (extract_public_ip, parse_proxy_line,
                           public_ipv4)


class UtilTests(unittest.TestCase):
    def test_parse_bare_and_scheme(self):
        self.assertEqual(parse_proxy_line("1.2.3.4:8080", "socks5"),
                         ("socks5", "1.2.3.4", 8080))
        self.assertEqual(parse_proxy_line("http://1.2.3.4:8080", "socks5"),
                         ("http", "1.2.3.4", 8080))
        self.assertEqual(parse_proxy_line("socks5://1.2.3.4:1080"),
                         ("socks5", "1.2.3.4", 1080))

    def test_parse_rejects_private_and_bad_ports(self):
        self.assertIsNone(parse_proxy_line("10.0.0.1:8080"))
        self.assertIsNone(parse_proxy_line("127.0.0.1:8080"))
        self.assertIsNone(parse_proxy_line("1.2.3.4:0"))
        self.assertIsNone(parse_proxy_line("1.2.3.4:99999"))
        self.assertIsNone(parse_proxy_line("not-a-proxy"))

    def test_public_ipv4(self):
        self.assertEqual(public_ipv4("8.8.8.8"), "8.8.8.8")
        self.assertIsNone(public_ipv4("192.168.1.1"))
        self.assertIsNone(public_ipv4("0.0.0.0"))

    def test_extract_public_ip(self):
        self.assertEqual(extract_public_ip('{"origin": "8.8.8.8"}'), "8.8.8.8")
        self.assertEqual(extract_public_ip("2001:4860:4860::8888"),
                         "2001:4860:4860::8888")
        self.assertIsNone(extract_public_ip("Maximum number of connections"))


class ScoreTests(unittest.TestCase):
    def test_stream_and_tls_rank_higher(self):
        once = compute_score(True, True, False, "anonymous", 3000, None, 0, 0)
        stream = compute_score(True, True, True, "anonymous", 3000, None, 0, 0)
        tls = compute_score(True, True, True, "anonymous", 3000, None, 0, 0,
                            tls_ok=True)
        self.assertLess(once, stream)
        self.assertLess(stream, tls)

    def test_transparent_is_penalized(self):
        normal = compute_score(True, True, False, "anonymous", 800, None)
        transparent = compute_score(True, True, False, "transparent", 800, None)
        self.assertLess(transparent, normal)
        self.assertLessEqual(transparent, 35)


if __name__ == "__main__":
    unittest.main()
