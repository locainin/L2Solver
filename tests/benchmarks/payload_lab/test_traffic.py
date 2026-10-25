"""Check the lab's controls independently of its network capture and analyzer."""

import base64
import gzip
import json
import unittest

from benchmarks.payload_lab.traffic import specimens


class PayloadLabTests(unittest.TestCase):
    def test_transforms_recover_original_bytes(self):
        samples = {sample.name: sample for sample in specimens()}
        plain = samples["plain"].wire
        self.assertEqual(bytes(byte ^ 0xA7 for byte in samples["xor-single"].wire), plain)
        self.assertEqual(bytes((byte - 73) % 256 for byte in samples["byte-add"].wire), plain)
        rotated = samples["rotate-bits"].wire
        self.assertEqual(bytes(((byte >> 3) | (byte << 5)) & 255 for byte in rotated), plain)
        layered = samples["layered"].wire
        self.assertEqual(gzip.decompress(base64.b64decode(layered[::-1], validate=True)), plain)

    def test_search_plans_omit_ground_truth(self):
        for sample in specimens():
            with self.subTest(sample=sample.name):
                self.assertFalse(any(check["kind"] == "sha256"
                                     for check in sample.plan["constraints"]))
                self.assertFalse(any("key" in family for family in sample.plan["families"]))
                self.assertLessEqual(sample.plan["max_candidates"], 1024)

    def test_specimen_plans_remain_independent(self):
        samples = specimens()
        for selected, sample in enumerate(samples):
            original = [json.dumps(other.plan, sort_keys=True) for other in samples]
            sample.plan["constraints"].append({"kind": "utf8"})
            for index, other in enumerate(samples):
                if index != selected:
                    self.assertEqual(json.dumps(other.plan, sort_keys=True), original[index])
            sample.plan["constraints"].pop()

    def test_json_lookalike_differs_from_original(self):
        samples = {sample.name: sample for sample in specimens()}
        control = samples["valid-json-control"]
        self.assertIsNone(control.expected)
        self.assertNotEqual(control.wire, samples["plain"].wire)
        self.assertEqual(json.loads(control.wire)["schema"], json.loads(samples["plain"].wire)["schema"])

    def test_corrupt_controls_fail_decompression(self):
        samples = {sample.name: sample for sample in specimens()}
        for name in ["damaged-gzip", "truncated-layer"]:
            with self.subTest(sample=name), self.assertRaises((ValueError, OSError, EOFError)):
                gzip.decompress(base64.b64decode(samples[name].wire[::-1], validate=True))

    def test_wrong_plaintext_matches_inference_period(self):
        samples = {sample.name: sample for sample in specimens()}
        sample = samples["xor-holdout-control"]
        family = sample.plan["families"][0]
        known = bytes(family["bytes"])
        offset = family["offset"]
        selected = sample.wire[offset:offset + len(known)]
        inferred = bytes(a ^ b for a, b in zip(selected[:3], known[:3]))
        recovered = bytes(byte ^ inferred[index % 3] for index, byte in enumerate(selected))
        self.assertEqual(recovered[:3], known[:3])
        self.assertNotEqual(recovered[3:len(known)], known[3:])


if __name__ == "__main__":
    unittest.main()
