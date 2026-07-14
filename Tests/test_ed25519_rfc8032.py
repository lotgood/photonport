#!/usr/bin/env python3
"""RFC 8032 conformance and tamper tests for the shared Ed25519 verifier."""

import importlib.util
import pathlib
import sys
import unittest

ROOT = pathlib.Path(__file__).resolve().parent.parent
SPEC = importlib.util.spec_from_file_location(
    "ed25519_rfc8032", ROOT / "scripts" / "evidence" / "ed25519_rfc8032.py"
)
MOD = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = MOD
SPEC.loader.exec_module(MOD)

# RFC 8032 §7.1 test vectors (seed, public key, message, signature).
VECTORS = [
    (
        "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60",
        "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a",
        "",
        "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b",
    ),
    (
        "4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb",
        "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c",
        "72",
        "92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00",
    ),
    (
        "c5aa8df43f9f837bedb7442f31dcb7b166d38535076f094b85ce3a2e0b4458f7",
        "fc51cd8e6218a1a38da47ed00230f0580816ed13ba3303ac5deb911548908025",
        "af82",
        "6291d657deec24024827e69c3abe01a30ce548a284743a445e3680d7db5ac3ac18ff9b538d16f290ae67f760984dc6594a7c15e9716ed28dc027beceea1ec40a",
    ),
]


class Ed25519Rfc8032Tests(unittest.TestCase):
    def test_rfc8032_vectors_verify_and_rederive(self):
        for seed_hex, pub_hex, msg_hex, sig_hex in VECTORS:
            seed = bytes.fromhex(seed_hex)
            pub = bytes.fromhex(pub_hex)
            msg = bytes.fromhex(msg_hex)
            sig = bytes.fromhex(sig_hex)
            self.assertEqual(MOD.public_key(seed), pub)
            self.assertEqual(MOD.sign(seed, msg), sig)
            self.assertTrue(MOD.verify(pub, msg, sig))

    def test_tampered_inputs_fail_closed(self):
        seed_hex, pub_hex, msg_hex, sig_hex = VECTORS[2]
        pub = bytes.fromhex(pub_hex)
        msg = bytes.fromhex(msg_hex)
        sig = bytes.fromhex(sig_hex)
        # Flipped message bit.
        self.assertFalse(MOD.verify(pub, b"\x00" + msg[1:], sig))
        # Flipped signature bit (R half and S half).
        self.assertFalse(MOD.verify(pub, msg, bytes([sig[0] ^ 1]) + sig[1:]))
        self.assertFalse(MOD.verify(pub, msg, sig[:-1] + bytes([sig[-1] ^ 1])))
        # Wrong public key.
        other_pub = bytes.fromhex(VECTORS[0][1])
        self.assertFalse(MOD.verify(other_pub, msg, sig))
        # Malformed lengths and types never raise; they return False.
        self.assertFalse(MOD.verify(pub[:-1], msg, sig))
        self.assertFalse(MOD.verify(pub, msg, sig[:-1]))
        self.assertFalse(MOD.verify(b"", msg, b""))
        # Non-canonical S (>= group order) is rejected.
        L = 2**252 + 27742317777372353535851937790883648493
        s_int = int.from_bytes(sig[32:], "little")
        bad_s = sig[:32] + int.to_bytes(s_int + L, 32, "little")
        self.assertFalse(MOD.verify(pub, msg, bad_s))
        # Non-canonical point encodings are rejected.
        self.assertFalse(MOD.verify(b"\xff" * 32, msg, sig))

    def test_signature_domain_separation(self):
        seed = bytes.fromhex(VECTORS[0][0])
        pub = MOD.public_key(seed)
        sig = MOD.sign(seed, b"payload-a")
        self.assertTrue(MOD.verify(pub, b"payload-a", sig))
        self.assertFalse(MOD.verify(pub, b"payload-b", sig))


if __name__ == "__main__":
    unittest.main()
