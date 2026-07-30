# JWTBlaze 🔥

> **JWT Secret Auditing Tool** — HS256 brute-force & RS256→HS256 algorithm confusion testing.  
> Supports GPU acceleration via **hashcat** with automatic CPU multiprocessing fallback.

```
╔══════════════════════════════════════════════════════════════════════╗
║                                                                      ║
║      ____.__      _______________________.__                         ║
║     |    /  \    /  \__    ___/\______   \  | _____  ________ ____   ║
║     |    \   \/\/   / |    |    |    |  _/  | \__  \ \___   // __ \  ║
║ /\__|    |\        /  |    |    |    |   \  |__/ __ \_/    /\  ___/  ║
║ \________| \__/\  /   |____|    |______  /____(____  /_____ \\___  > ║
║                 \/                     \/          \/      \/    \/  ║
║                                                                      ║
║   [ JWT Secret Auditor ] [ HS256 Brute-force + Alg Confusion ]       ║
║   Author  : srsoumyax11                                              ║
║   GitHub  : https://github.com/srsoumyax11                           ║
║   Engines : GPU (hashcat) → CPU multiprocessing (auto-fallback)      ║
╚══════════════════════════════════════════════════════════════════════╝
```

---

## Features

| Feature | Details |
|---|---|
| ⚡ GPU acceleration | Via **hashcat** mode `16500` (NVIDIA / AMD / Intel GPU) |
| 🧵 CPU multiprocessing | All cores used in parallel when hashcat isn't installed |
| 🔀 Algorithm confusion | Tests RS256 / ES256 tokens for HS256 key confusion vulnerability |
| 🖥️ Cross-platform | Works on **Windows** and **Linux** |
| 📦 Zero extra deps | Stdlib only (`hmac`, `hashlib`, `base64`) — no PyJWT needed |

---

## Requirements

- Python 3.10+
- *(Optional but recommended)* [hashcat](https://hashcat.net/hashcat/) for GPU acceleration

### Install hashcat

| Platform | Command |
|---|---|
| **Windows** | Download from [hashcat.net](https://hashcat.net/hashcat/), extract, add to `PATH` |
| **Linux (Debian/Ubuntu)** | `sudo apt install hashcat` |
| **Linux (Fedora/RHEL)** | `sudo dnf install hashcat` |
| **Linux (Arch)** | `sudo pacman -S hashcat` |

> No other Python packages need to be installed. The script uses stdlib only.

---

## Usage

### Basic syntax

```bash
python jwt_bypass.py --token <JWT> --wordlist <WORDLIST>
```

### Arguments

| Argument | Required | Description |
|---|---|---|
| `--token` | ✅ | Full JWT string (all 3 parts: `header.payload.signature`) |
| `--wordlist` | ✅ | Path to a plaintext wordlist file (one secret per line) |
| `--workers` | ❌ | Number of CPU workers (default: all cores). Only used in CPU mode. |
| `--cpu` | ❌ | Force CPU mode — skips hashcat even if it's installed |

---

## Examples

### 1. Standard HS256 brute-force (auto-detects GPU or CPU)

```bash
python jwt_bypass.py \
  --token eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U \
  --wordlist rockyou.txt
```

### 2. RS256 token — algorithm confusion test

The script auto-detects `alg: RS256` in the header and switches to confusion mode,
testing whether the server accepts an HS256 signature (a known JWT vulnerability).

```bash
python jwt_bypass.py \
  --token eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9.eyJzdWIiOiIxMjM0In0.<sig> \
  --wordlist rockyou.txt
```

### 3. Force CPU only (useful when GPU is busy)

```bash
python jwt_bypass.py --token <JWT> --wordlist rockyou.txt --cpu
```

### 4. Limit to 2 CPU workers (leave cores free for other work)

```bash
python jwt_bypass.py --token <JWT> --wordlist rockyou.txt --cpu --workers 2
```

### 5. Using a custom wordlist

```bash
python jwt_bypass.py --token <JWT> --wordlist /path/to/custom_secrets.txt
```

---

## How it works

```
                  ┌─────────────────────────────┐
                  │     Parse JWT header         │
                  │  Detect declared algorithm   │
                  └────────────┬────────────────┘
                               │
               ┌───────────────▼────────────────┐
               │  Is hashcat installed + on PATH? │
               └──────┬──────────────┬───────────┘
                      │ YES          │ NO
              ┌───────▼──────┐  ┌───▼──────────────────┐
              │  GPU Engine  │  │  CPU Engine           │
              │  hashcat     │  │  multiprocessing      │
              │  mode 16500  │  │  (all cores, chunked) │
              │  (JWT HS256) │  └──────────┬────────────┘
              └──────┬───────┘             │
                     └──────────┬──────────┘
                                │
                    ┌───────────▼───────────┐
                    │  Signature match?      │
                    │  → Print secret key   │
                    └───────────────────────┘
```

### Acceleration tiers

| Tier | Engine | Speed (estimate) |
|---|---|---|
| 🥇 GPU | hashcat (NVIDIA/AMD/Intel) | **100M–1B+ keys/sec** |
| 🥈 CPU | Python multiprocessing (all cores) | ~800K–2M keys/sec |

---

## Sample Output

```
╔══════════════════════════════════════════════════════════════════════╗
║   [ JWT Secret Auditor ] [ HS256 Brute-force + Alg Confusion ]      ║
║   Author  : srsoumyax11  │  github.com/srsoumyax11                   ║
╚══════════════════════════════════════════════════════════════════════╝

  Token Algorithm  : HS256
  Platform         : Linux x86_64
  Audit Mode       : Standard HS256 brute-force
  Engine           : GPU via hashcat (/usr/bin/hashcat)
  Wordlist         : rockyou.txt

========================================================================
[hashcat progress output...]

[+] SECRET FOUND  →  supersecret123
```

---

## Legal Disclaimer

> **This tool is intended for authorized security testing and penetration testing only.**  
> Only use it against systems you own or have explicit written permission to test.  
> Unauthorized use against systems you do not own is illegal and unethical.  
> The author assumes no liability for misuse.

---

## Author

**srsoumyax11** — [github.com/srsoumyax11](https://github.com/srsoumyax11)
