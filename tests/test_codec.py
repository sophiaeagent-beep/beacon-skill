import unittest

from beacon_skill.codec import decode_envelopes, encode_envelope


class TestCodec(unittest.TestCase):
    def test_encode_decode_roundtrip(self) -> None:
        payload = {"v": 1, "kind": "hello", "from": "a", "to": "b", "ts": 123}
        txt = f"hi\n\n{encode_envelope(payload)}\nbye"
        envs = decode_envelopes(txt)
        self.assertEqual(len(envs), 1)
        self.assertEqual(envs[0]["kind"], "hello")

