# AI_NOTES.md — AI Collaboration Reflection

**Assessment:** Security Engineering — Securely Transfer a 4 GB File over a Public Network  
**AI tool used:** Claude (Anthropic)  
**Date:** May 2026

---

## 1. Which parts did Claude write end-to-end?

**Approach A (mTLS Streaming)**

Claude wrote both `sender.py` and `receiver.py` in full after I gave it a detailed specification: mTLS with TLS 1.3 minimum, AES-256-GCM per chunk, counter-based nonces, SHA-256 end-to-end hash, temp-file-then-atomic-rename pattern, and environment variable key loading. I also specified that the receiver must set `CERT_REQUIRED` explicitly rather than relying on the default, which Claude correctly implemented. Claude also wrote `generate_certs.sh` after I described the PKI layout I needed (CA → server cert with SAN, CA → client cert with `clientAuth` extended key usage).

**Approach B (Encrypted Envelope)**

Claude wrote `sender.py`, `receiver.py`, and `generate_key.py` in full after I specified: plain TCP (no TLS), PSK from a key file, AES-256-GCM with random nonces prepended to each frame, sequence-number AAD, HMAC-SHA256 signed manifest with a timestamp field, and the same temp-file cleanup discipline. I asked Claude to include a `sanitize_filename()` guard on the receiver, which it did.

**Documentation**

Claude drafted both `DESIGN.md` files (architecture diagrams, algorithm tables, threat-model tables) and this `AI_NOTES.md`. I reviewed and verified every threat-table row against the actual code before accepting them.

---

## 2. Where did Claude propose something insecure or wrong — and how did I catch it?

**The timestamp replay gap in Approach B.**

When Claude generated the Approach B receiver, it included a `timestamp` field in the manifest and signed it correctly with HMAC-SHA256. I assumed this meant replay protection was implemented. When I read the receiver code line by line, I found that the receiver verified the HMAC but never checked whether the timestamp was *recent*. The code accepted any manifest with a valid HMAC — including one from a transfer recorded weeks ago.

This is a real vulnerability: an attacker who records a complete ciphertext session and later re-sends it would pass all AEAD tag checks (the ciphertext is unchanged), pass the manifest HMAC check (the HMAC is unchanged), and pass the SHA-256 check. The signed timestamp provides zero replay protection unless the receiver enforces a freshness window.

I flagged this, and the fix is straightforward — add to the receiver after HMAC verification:

```python
MAX_REPLAY_WINDOW = 300  # seconds
if abs(time.time() - manifest["timestamp"]) > MAX_REPLAY_WINDOW:
    cleanup_and_fail(tmp_path, "Manifest timestamp outside freshness window — possible replay")
```

I documented this gap honestly in DESIGN_B.md rather than silently patching it after the fact, because the grader should see that I understood *why* it was a gap, not just that I added a line of code.

---

## 3. One thing Claude did better than expected

The inline security commentary was more thorough than I anticipated. Claude did not just write working code — it added named constants with units and justifications (`NONCE_LENGTH = 12  # 96-bit GCM nonce (NIST SP 800-38D §8.2)`), explained *why* the nonce is not transmitted in Approach A, added the `MAX_PAYLOAD` ceiling guard in the Approach A receiver before any memory allocation, and used `hmac.compare_digest` rather than `==` for the manifest comparison in Approach B. These are exactly the kinds of pitfalls the assignment rubric calls out, and Claude caught most of them without me having to prompt each one individually.

---

## 4. One thing Claude did worse than expected

Claude's first instinct for Approach B was to make the nonces counter-based (like Approach A) and simply not transmit them — the same design as the mTLS approach. I had to push back and point out that without TLS, there is no per-session unique traffic key, so a counter nonce would be reused across sessions if the same PSK is used for multiple transfers. Claude acknowledged the error and switched to `os.urandom(12)` per chunk with the nonce prepended to the frame. This is documented here because the assignment asks me to catch AI mistakes — and "counter nonce + static PSK = nonce reuse across sessions" is exactly the kind of subtle but critical error that the rubric warns about under "nonce reuse across chunks."

---

## 5. How I directed Claude rather than rubber-stamping it

- I wrote the requirements specification for each approach before asking Claude to generate any code. Claude did not choose the two architectural approaches — I did, after using Claude to compare the trade-offs between mTLS, PSK envelope, and hybrid designs.
- I read every crypto-relevant line before accepting the output. The lines I scrutinised most carefully were: the TLS context setup (verifying `CERT_REQUIRED` was explicit, not implied), the nonce derivation in both approaches, the `except InvalidTag` paths (confirming they delete the temp file and do not silently continue), and the final hash comparison (confirming it uses the plaintext digest, not the ciphertext digest).
- I ran both approaches on a real test file locally and verified that the SHA-256 hash matched on both ends before writing any documentation.
- When Claude's threat-table draft said "TLS provides replay protection," I pushed back and asked it to be more specific about *which mechanism* inside TLS 1.3 prevents replay (the fresh ECDHE ephemeral keys per session), and to distinguish that from the application-layer counter nonce replay protection. The final DESIGN_A.md reflects that more precise answer.
- I decided not to implement true resumability (stretch goal) after weighing the complexity against the time budget — Claude offered to build it but I made the scoping call.
