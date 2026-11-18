# Lab: Crypto Server Client

A Python client connecting to AWS cloud server. It encrypts files locally with AES-256-GCM key, ask the server to decrypt them, and computes the course HMAC for the server to verify. Messages follow `crypto_message_spec_v2.md`.

**Result:** all tests passed against the real server. Decryption returned the original files, the server answered VERIFIED for a correct HMAC, and it answered FAILED after one byte of the file was changed.

## Results (`Results/`)

| File | What it shows |
|---|---|
| `test_vectors_output.txt` | Framing, AES-GCM and HMAC match the spec's section 9 test vectors |
| `real_server_output.txt` | get_key, decrypt round trip, VERIFIED and FAILED against the real server |
| `hello.txt` → `hello.txt.enc` → `hello.dec.txt` | Text file encrypted locally and decrypted by the server |
| `hello.txt.hmac` | Course HMAC of `hello.txt` |
| `hello_modified.txt` | `hello.txt` with one letter changed, used to produce FAILED |
| `tada.wav` → `tada.wav.enc` → `tada.dec.wav` | Binary (audio) file round trip; the decrypted file plays normally |
| `tada.wav.hmac` | Course HMAC of `tada.wav` |


Key files (`.key`, `.hmackey`) are left out of the repository on purpose, because keys should not be stored in a repository. 

## Documents

- `Requirements_v1.md`, `Requirements_v2.md`: requirements before and after Claude's clarification questions
- `design_v1.md`: design, with a section on changes made during the build
- `interrogation.md`: questions to Claude, my decisions and what I learned
- `project_chat.md`: the full Claude conversation
- `crypto_client/`: the client code and test scripts
