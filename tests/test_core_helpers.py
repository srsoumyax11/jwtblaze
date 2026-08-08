# Simple pytest tests for jwtblaze core helpers

import base64
import hmac
import hashlib
import json

from jwtblaze.core import b64url_decode, parse_token_header, build_signing_input, verify_hs256


def make_sample_token(secret: str = "testsecret") -> str:
    header = {"alg": "HS256", "typ": "JWT"}
    payload = {"sub": "1", "name": "Test"}

    def b64url(x: bytes) -> str:
        return base64.urlsafe_b64encode(x).rstrip(b"=").decode()

    signing = f"{b64url(json.dumps(header).encode())}.{b64url(json.dumps(payload).encode())}"
    sig = hmac.new(secret.encode(), signing.encode(), hashlib.sha256).digest()
    token = signing + "." + b64url(sig)
    return token


def test_b64url_decode_and_header():
    token = make_sample_token()
    header = parse_token_header(token)
    assert header is not None
    assert header.get("alg") == "HS256"


def test_build_signing_and_verify():
    secret = "testsecret"
    token = make_sample_token(secret)
    signing_input, expected_sig = build_signing_input(token)
    assert verify_hs256(signing_input, expected_sig, secret) is True
    assert verify_hs256(signing_input, expected_sig, "wrong") is False
