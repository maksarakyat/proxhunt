import os
import tempfile
import unittest

from proxhunt.store import Store
from proxhunt.util import now


class StoreTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.store = Store(os.path.join(self.tmp.name, "pool.sqlite3"))

    def tearDown(self):
        self.store.close()
        self.tmp.cleanup()

    def test_apply_and_filter(self):
        self.store.upsert_candidates([
            ("http", "8.8.8.8:8080", {"source": "test", "country": "US"}),
            ("socks5", "9.9.9.9:1080", {"source": "test"}),
        ])
        self.store.apply_results([
            {"proto": "http", "addr": "8.8.8.8:8080",
             "http_ok": True, "https_ok": True, "tls_ok": True,
             "stream_ok": True, "mode": "stream", "anon": "elite",
             "exit_ip_http": "8.8.8.8", "exit_ip_https": "8.8.8.8",
             "latency_ms": 120, "successes": 4, "fails": 0},
        ])
        rows = self.store.list_proxies(limit=10, alive_minutes=0)
        self.assertEqual(len(rows), 1)
        row = rows[0]
        self.assertEqual(row["addr"], "8.8.8.8:8080")
        self.assertEqual(row["mode"], "stream")
        self.assertEqual(row["tls_ok"], 1)
        self.assertGreater(row["score"], 0)

        stream = self.store.list_proxies(limit=10, mode="stream", alive_minutes=0)
        self.assertEqual(len(stream), 1)
        tls = self.store.list_proxies(limit=10, tls_only=True, alive_minutes=0)
        self.assertEqual(len(tls), 1)

    def test_dead_result_is_not_listed(self):
        self.store.upsert_candidates([("http", "8.8.8.8:8080", {})])
        self.store.apply_results([
            {"proto": "http", "addr": "8.8.8.8:8080", "fails": 1},
        ])
        self.assertEqual(self.store.list_proxies(limit=10, alive_minutes=0), [])

    def test_freshness_filter(self):
        self.store.upsert_candidates([("http", "8.8.8.8:8080", {})])
        self.store.apply_results([
            {"proto": "http", "addr": "8.8.8.8:8080", "http_ok": True,
             "successes": 1},
        ])
        self.assertEqual(len(self.store.list_proxies(limit=10, alive_minutes=60)), 1)
        self.store.conn.execute(
            "UPDATE proxies SET last_ok=? WHERE addr=?",
            (now() - 7200, "8.8.8.8:8080"))
        self.store.conn.commit()
        self.assertEqual(self.store.list_proxies(limit=10, alive_minutes=60), [])


if __name__ == "__main__":
    unittest.main()
