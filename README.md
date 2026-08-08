# JWTBlaze 🔥

[![Python](https://img.shields.io/badge/python-3.10%2B-blue)](https://www.python.org)
[![License](https://img.shields.io/badge/license-MIT-green)](LICENSE)
[![CI](https://img.shields.io/badge/ci-pending-lightgrey)](https://github.com/srsoumyax11/jwtblaze/actions)

A compact CLI for auditing JWT secrets: HS256 brute-force and RS256→HS256
algorithm-confusion testing. Supports GPU acceleration via hashcat and a
pure-Python multiprocessing fallback.

Quick start

1. Clone the repo and create a venv:

```bash
git clone https://github.com/srsoumyax11/jwtblaze.git
cd jwtblaze
python -m venv .venv
source .venv/bin/activate  # or .venv\Scripts\activate on Windows
```

2. Run the script (CPU mode):

```bash
python jwt_bypass.py --token <JWT> --wordlist samples/sample_wordlist.txt --cpu
```

Responsible usage

This tool is intended for authorized security testing only. Do not use it on
systems you do not own or do not have explicit written permission to test. See
SECURITY.md for details.

More details, examples, and the original ASCII banner are below.

---

(Original README content retained below — see full project README for examples and details.)
