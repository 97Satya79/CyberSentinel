import unittest

from storage import compute_hash_code


class StorageTests(unittest.TestCase):
    def test_hash_is_stable_and_endpoint_specific(self):
        first = compute_hash_code(1, "SQL Injection", 89, "127.0.0.1", 5050, "/login")
        same = compute_hash_code(1, "SQL Injection", 89, "127.0.0.1", 5050, "/login")
        other_path = compute_hash_code(1, "SQL Injection", 89, "127.0.0.1", 5050, "/admin")

        self.assertEqual(first, same)
        self.assertEqual(len(first), 64)
        self.assertNotEqual(first, other_path)


if __name__ == "__main__":
    unittest.main()
