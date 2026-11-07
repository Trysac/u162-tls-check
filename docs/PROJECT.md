# Project Record

## Objective
To provide lightweight, fast, and dependency-free TLS inspection for certificate chains and live network endpoints, outputting deterministic, stable finding codes for automated monitoring.

## Scope
- Live TLS probing (handshake inspection).
- Certificate chain validation against system or custom root pools.
- Identifying expiry, validity range, hostname mismatch, weak keys (RSA < 2048), weak signatures (MD5/SHA-1), and protocol versions.

## Out-of-Scope
- CLI tool implementation.
- OCSP or CRL checks.
- Cipher suite enumeration.
- Certificate transparency logs.
- STARTTLS support.

## Factory run u162 (measured from API usage)

| Phase | Model | Batch | Input | Output | Cache write | Cache read | Cost (USD) |
|---|---|---|---|---|---|---|---|
| generation | gemini-3.8-flash | yes | 4255 | 14204 | 0 | 0 | 0.0282 |
| fix-1 | gemini-3.1-flash-lite | no | 13626 | 177 | 0 | 0 | 0.0037 |
| fix-2 | gemini-3.1-flash-lite | no | 22781 | 187 | 0 | 18297 | 0.0064 |
| fix-3 | gemini-3.1-flash-lite | no | 109147 | 3687 | 0 | 832394 | 0.0536 |
| fix-4 | gemini-3.1-flash-lite | no | 72151 | 1951 | 0 | 337559 | 0.0294 |
| fix-1 | gemini-3.8-flash | no | 59290 | 879 | 0 | 218382 | 0.0641 |
| fix-2 | gemini-3.8-flash | no | 76165 | 915 | 0 | 326456 | 0.0850 |
| audit | gemini-3.1-flash-lite | no | 22745 | 135 | 0 | 6116 | 0.0060 |
| docs | gemini-3.1-flash-lite | no | 3348 | 1294 | 0 | 0 | 0.0028 |

Total: $0.2794. Prices: Anthropic list prices.
