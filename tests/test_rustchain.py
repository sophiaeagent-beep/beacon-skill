import json
import unittest

from beacon_skill.transports.rustchain import RustChainClient, RustChainKeypair


class TestRustChainSigning(unittest.TestCase):
    def test_sign_transfer_shape(self) -> None:
        kp = RustChainKeypair.generate()
        c = RustChainClient(base_url="https://example.invalid", verify_ssl=True)
        payload = c.sign_transfer(
            private_key_hex=kp.private_key_hex,
            to_address="RTC" + ("0" * 40),
            amount_rtc=1.5,
            memo="test",
            nonce=123,
        )
        self.assertEqual(payload["from_address"], kp.address)
        self.assertEqual(payload["nonce"], 123)
        self.assertEqual(payload["amount_rtc"], 1.5)
        # Basic sanity: JSON serialization should work.
        json.dumps(payload)

