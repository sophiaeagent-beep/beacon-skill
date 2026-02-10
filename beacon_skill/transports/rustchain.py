import hashlib
import json
import time
from dataclasses import dataclass
from typing import Any, Dict, Optional

import requests
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PrivateFormat, PublicFormat, NoEncryption


class RustChainError(RuntimeError):
    pass


def _rtc_address_from_public_key_bytes(pubkey: bytes) -> str:
    h = hashlib.sha256(pubkey).hexdigest()[:40]
    return f"RTC{h}"


@dataclass(frozen=True)
class RustChainKeypair:
    private_key_hex: str
    public_key_hex: str
    address: str

    @staticmethod
    def generate() -> "RustChainKeypair":
        sk = Ed25519PrivateKey.generate()
        sk_bytes = sk.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption())
        pk_bytes = sk.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
        return RustChainKeypair(
            private_key_hex=sk_bytes.hex(),
            public_key_hex=pk_bytes.hex(),
            address=_rtc_address_from_public_key_bytes(pk_bytes),
        )

    @staticmethod
    def from_private_key_hex(private_key_hex: str) -> "RustChainKeypair":
        sk_bytes = bytes.fromhex(private_key_hex)
        if len(sk_bytes) != 32:
            raise ValueError("private_key_hex must be 32 bytes (64 hex chars)")
        sk = Ed25519PrivateKey.from_private_bytes(sk_bytes)
        pk_bytes = sk.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
        return RustChainKeypair(
            private_key_hex=private_key_hex,
            public_key_hex=pk_bytes.hex(),
            address=_rtc_address_from_public_key_bytes(pk_bytes),
        )


class RustChainClient:
    def __init__(
        self,
        base_url: str = "https://50.28.86.131",
        timeout_s: int = 20,
        verify_ssl: bool = False,
    ):
        self.base_url = base_url.rstrip("/")
        self.timeout_s = timeout_s
        self.verify_ssl = verify_ssl
        self.session = requests.Session()
        self.session.headers.update({"User-Agent": "Beacon/0.1.0 (Elyan Labs)"})

    def _request(self, method: str, path: str, **kwargs) -> Dict[str, Any]:
        url = f"{self.base_url}{path}"
        resp = self.session.request(method, url, timeout=self.timeout_s, verify=self.verify_ssl, **kwargs)
        try:
            data = resp.json()
        except Exception:
            data = {"raw": resp.text}
        if resp.status_code >= 400:
            raise RustChainError(data.get("error") or f"HTTP {resp.status_code}")
        return data

    def balance(self, miner_id: str) -> Dict[str, Any]:
        return self._request("GET", "/wallet/balance", params={"miner_id": miner_id})

    def sign_transfer(
        self,
        *,
        private_key_hex: str,
        to_address: str,
        amount_rtc: float,
        memo: str = "",
        nonce: Optional[int] = None,
    ) -> Dict[str, Any]:
        kp = RustChainKeypair.from_private_key_hex(private_key_hex)
        sk = Ed25519PrivateKey.from_private_bytes(bytes.fromhex(kp.private_key_hex))
        if nonce is None:
            nonce = int(time.time() * 1000)

        tx_data = {
            "from": kp.address,
            "to": to_address,
            "amount": float(amount_rtc),
            "memo": memo,
            "nonce": nonce,
        }
        msg = json.dumps(tx_data, sort_keys=True, separators=(",", ":")).encode()
        sig = sk.sign(msg).hex()

        return {
            "from_address": kp.address,
            "to_address": to_address,
            "amount_rtc": float(amount_rtc),
            "nonce": nonce,
            "signature": sig,
            "public_key": kp.public_key_hex,
            "memo": memo,
        }

    def transfer_signed(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        return self._request("POST", "/wallet/transfer/signed", json=payload, headers={"Content-Type": "application/json"})

