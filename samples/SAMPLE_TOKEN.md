# Generating a sample JWT (HS256) for testing

This file shows how to generate a small HS256-signed JWT locally for testing
with jwt_bypass.py. Do not use these tokens against any remote system.

Example Python command (no external libs required):

```bash
python - <<'PY'
import base64, json, hmac, hashlib

def b64url(x: bytes) -> str:
    return base64.urlsafe_b64encode(x).rstrip(b"=").decode()

header = {"alg": "HS256", "typ": "JWT"}
payload = {"sub": "1234567890", "name": "Test User"}
secret = "testsecret"

signing_input = f"{b64url(json.dumps(header).encode())}.{b64url(json.dumps(payload).encode())}"
sig = hmac.new(secret.encode(), signing_input.encode(), hashlib.sha256).digest()

token = signing_input + "." + b64url(sig)
print(token)
PY
```

Use the printed token with the included sample wordlist to test CPU mode:

```bash
python jwt_bypass.py --token <printed_token> --wordlist samples/sample_wordlist.txt --cpu
```
