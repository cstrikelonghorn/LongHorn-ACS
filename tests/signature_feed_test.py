import hashlib
import importlib.util
import json
from pathlib import Path
import unittest

spec = importlib.util.spec_from_file_location('sync_signatures', Path(__file__).resolve().parents[1] / 'tools' / 'sync_signatures.py')
sync = importlib.util.module_from_spec(spec)
spec.loader.exec_module(sync)

class FeedTests(unittest.TestCase):
    def payload(self, **changes):
        value = {'publishedAt': '2026-01-01T00:00:00Z', 'hashes': [{'sha256': 'a' * 64, 'family': 'Test fixture', 'source': 'https://example.invalid/review'}]}
        value.update(changes)
        raw = json.dumps(value).encode()
        return raw, hashlib.sha256(raw).hexdigest()

    def test_valid_hash_only_rule(self):
        result = sync.validate_feed(*self.payload())
        self.assertEqual(result['signatures'][0]['match'], {'sha256': ['a' * 64]})

    def test_modified_feed_rejected(self):
        raw, sha = self.payload()
        with self.assertRaises(ValueError): sync.validate_feed(raw + b' ', sha)

    def test_future_feed_rejected(self):
        with self.assertRaises(ValueError): sync.validate_feed(*self.payload(publishedAt='2999-01-01T00:00:00Z'))

    def test_empty_feed_rejected(self):
        with self.assertRaises(ValueError): sync.validate_feed(*self.payload(hashes=[]))

    def test_regex_cannot_be_imported(self):
        with self.assertRaises(ValueError): sync.validate_feed(*self.payload(hashes=[{'sha256': '.*', 'family': 'Bad', 'source': 'https://example.invalid'}]))

if __name__ == '__main__': unittest.main()
