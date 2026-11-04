import os, sys, unittest
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import shard_mcp as m

class T(unittest.TestCase):
    def test_key_regex(self):
        self.assertTrue(m.KEY_RE.match("itest-1"))
        self.assertFalse(m.KEY_RE.match("-bad"))
        self.assertFalse(m.KEY_RE.match("x"*80))
    def test_default_url_local(self):
        self.assertIn("127.0.0.1", m.URL)

if __name__ == "__main__": unittest.main()
