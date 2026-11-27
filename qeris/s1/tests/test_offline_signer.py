"""Tests for the offline ML-DSA-65 policy authority CLI."""

import json
import os
from pathlib import Path
import tempfile
import unittest

from qeris.policy.offline_signer import (
    generate_authority_keypair,
    sign_policy_file,
)


class TestOfflinePolicySigner(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.policy = {
            "flow_id": "temperature_01",
            "sensitivity": "LOW",
            "minimum_mode": "CLASSICAL",
            "policy_version": 1,
            "authority_id": "authority_test",
        }

    def tearDown(self):
        self.temp.cleanup()

    def test_generate_keypair_and_refuse_overwrite(self):
        prefix = self.root / "authority"
        private_path, public_path = generate_authority_keypair(prefix)
        self.assertTrue(private_path.is_file())
        self.assertTrue(public_path.is_file())
        self.assertGreater(private_path.stat().st_size, 0)
        self.assertGreater(public_path.stat().st_size, 0)
        if os.name == "posix":
            self.assertEqual(private_path.stat().st_mode & 0o777, 0o600)
        with self.assertRaises(FileExistsError):
            generate_authority_keypair(prefix)

    def test_sign_single_policy_envelope(self):
        private_path, _ = generate_authority_keypair(self.root / "authority")
        input_path = self.root / "policy.json"
        output_path = self.root / "signed.json"
        input_path.write_text(json.dumps(self.policy), encoding="utf-8")
        sign_policy_file(input_path, private_path, output_path, authority_id="authority_test")
        result = json.loads(output_path.read_text(encoding="utf-8"))
        self.assertEqual(set(result), {"temperature_01"})
        self.assertEqual(result["temperature_01"]["policy"], self.policy)
        self.assertEqual(result["temperature_01"]["sig_alg"], "ML-DSA-65")
        self.assertTrue(result["temperature_01"]["signature"])
        self.assertNotIn(private_path.read_bytes().hex(), output_path.read_text(encoding="utf-8"))
        with self.assertRaises(FileExistsError):
            sign_policy_file(input_path, private_path, output_path)

    def test_sign_flow_keyed_bundle(self):
        private_path, _ = generate_authority_keypair(self.root / "authority")
        second = dict(self.policy, flow_id="pressure_03", policy_version=2)
        input_path = self.root / "bundle.json"
        output_path = self.root / "bundle.signed.json"
        input_path.write_text(json.dumps({"temperature_01": self.policy, "pressure_03": second}), encoding="utf-8")
        sign_policy_file(input_path, private_path, output_path, authority_id="authority_test")
        result = json.loads(output_path.read_text(encoding="utf-8"))
        self.assertEqual(set(result), {"temperature_01", "pressure_03"})

    def test_authority_id_mismatch_rejected(self):
        private_path, _ = generate_authority_keypair(self.root / "authority")
        input_path = self.root / "policy.json"
        input_path.write_text(json.dumps(self.policy), encoding="utf-8")
        with self.assertRaises(ValueError):
            sign_policy_file(input_path, private_path, self.root / "out.json", authority_id="other_authority")

    def test_empty_bundle_rejected(self):
        private_path, _ = generate_authority_keypair(self.root / "authority")
        input_path = self.root / "empty.json"
        input_path.write_text("{}", encoding="utf-8")
        with self.assertRaises(ValueError):
            sign_policy_file(input_path, private_path, self.root / "out.json")


if __name__ == "__main__":
    unittest.main()
