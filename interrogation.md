# Interrogation log

This log records how I questioned Claude while building the crypto server client. Round 1 covers the clarification questions Claude raised on `Requirements_v1.md`, with my decision and reason for each; these produced `requirements_v2.md`. Round 2 covers the "why" questions I asked about the design once the client worked. A third section lists decisions I changed during the build.

---

## Round 1: Clarification questions on Requirements v1

Claude read `crypto_message_spec_v2.md` and `Requirements_v1.md` before writing any code and raised 39 points. The question is summarised, followed by my decision and reason.

### A. Requirements vs. spec

| # | Claude's question | My decision and reason |
|---|---|---|
| A1 | The v1 error message guesses a cause, but the spec says the server error is deliberately generic. | Use a neutral message. Causes the client can check (size, key files, username format) are checked locally and get their own messages, so anything that reaches the server and fails cannot be diagnosed by the client. |
| A2 | Screenshots in `Results/` would show the username and IP. | Mask both in every screenshot, because the spec says to keep the username out of anything shared. |
| A3 | The spec's own `exchange()` adds spaces to the JSON, so it cannot match the compact framing vector. | Use compact separators and the order `type, username, payload_len`. Matching the vector byte for byte is the only way the framing test means anything. |
| A4 | Size limits are only required for Encrypt and Compute HMAC. | Add them to Decrypt and Verify too. Otherwise the server resets the connection, which looks like a network failure. |
| A5 | Should there be a fake local server? | Yes at first, for testing before the server IP was available. (Later removed; see section 3.) |
| A6 | Which Python version? | 3.9 or newer, as in the spec's reference snippet. Cross-platform code only. |
| A7 | Section 11 still names a v1 spec file. | Ignore it. v2 replaces v1. |

### B. Files, naming and paths

| # | Claude's question | My decision and reason |
|---|---|---|
| B1 | Does "same base name" give `wave.key` or `wave.wav.key`? | `wave.wav.key`, matching the spec, so files work with the instructor's client. |
| B2 | How is the decrypted file named for odd file names? | Remove `.enc`, insert `.dec` before the last extension only (`a.tar.gz.enc` gives `a.tar.dec.gz`). Refuse files not ending in `.enc`. The real extension stays last so the file still opens. |
| B3 | Where should the program look for the original? | Only next to the `.enc` file, because that is where Encrypt put the pair. |
| B4 | What if the original is missing? | Show "comparison skipped" as a notice, not an error. |
| B5 | Folder chooser or Save-As for Encrypt? | Save-As with `<name>.enc` filled in; the `.key` is always written beside the `.enc`. |
| B6 | What happens if output files already exist? | Never overwrite silently. Losing a `.key` makes its `.enc` unrecoverable. |
| B7 | Trailing newline in base64 files? | Write none; strip whitespace when reading, so files edited in Notepad still work. |
| B8 | Validate key and HMAC files locally? | Yes: strict base64 decoding to exactly 32 bytes, checked before contacting the server. |

### C. Key handling

| # | Claude's question | My decision and reason |
|---|---|---|
| C1 | One key slot or two? | Two. Both buttons call `get_key`, so one slot would let an HMAC key silently replace the AES key. |
| C2 | How long is a key kept? | Until a new key of the same kind is fetched. Reuse is safe because every file gets a fresh nonce. |
| C3 | Compute HMAC without a key? | Show "Get an HMAC key first", the same rule as Encrypt. |
| C4 | Decrypt ignores the key in memory. Intended? | Yes. The key in memory may belong to a different file; the `.key` saved with the `.enc` is the right one. |
| C5 | Check the length of the key from the server? | Yes. Reject anything that is not 32 bytes. |
| C6 | Does "never display a key" cover exceptions? | Yes. Status lines and error text never contain keys or header contents. |

### D. User interface and behaviour

| # | Claude's question | My decision and reason |
|---|---|---|
| D1 | "Message type" is wrong for local operations. | Rename the dropdown "Operation". |
| D2 | Which inputs per operation? | Browse button per file field, one Run button per operation. |
| D3 | How should an error look different from FAILED? | Single status line: VERIFIED green, FAILED red, errors black with an "ERROR:" prefix, so colour is not the only signal. |
| D4 | Threading? | Network calls off the main thread; Run buttons disabled while a call runs. |
| D5 | Timeouts? | 30 seconds for connect and read, matching the reference client and shorter than the server's 60-second idle limit. |
| D6 | Validate the port and username locally? | Yes, so a typo gets a specific message instead of the server's generic error. |
| D7 | Malformed replies? | Cap the header at 1000 bytes and the payload at 1 MiB; show "Unexpected reply from server". |
| D8 | Empty files and very short `.enc` files? | Empty files allowed (the spec has a vector for them). A `.enc` under 28 bytes is refused because it cannot hold a nonce and a tag. |

### E. Code structure and tests

| # | Claude's question | My decision and reason |
|---|---|---|
| E1 | Tests must import functions from `client.py`. | Acceptable. "One file" means one file for the app. |
| E2 | The AES vector needs a fixed nonce, but real files need a random one. | Add an optional `nonce` parameter used only by the tests. The GUI never passes it. |
| E3 | Test style? | Plain asserts with a PASS line each, including a check that the HMAC is not the standard-HMAC value `411b9a51…`. |
| E4 | When to build the GUI? | Last, after the logic is proven. |
| E5 | Who runs the real-server steps? | I run them and report back, since the IP and username must not be in the code. |
| E6 | Wording details ("block", `hashlib`). | "Block" means each function and section. SHA-256 comes only from the Cryptography library. |

### F. Submission outputs

| # | Claude's question | My decision and reason |
|---|---|---|
| F1 | Which test files? | `hello.txt` (to match the section 9 vectors) and a small binary file (`tada.wav`), run inside `Results/`. |
| F2 | How to produce FAILED without touching the original? | Copy `hello.txt` to `hello_modified.txt`, change one byte, and verify it against `hello.txt`'s HMAC files. |
| F3 | Who takes screenshots? | I do, with the IP and username masked. |
| F4 | Commit the key files? | Originally yes. Changed later; see section 3. |

---

## Round 2: Why questions

### Part A: AES-GCM

**Q1. Why does the spec use AES-GCM rather than CBC or CTR?**
- *Claude's answer (summary):* CBC and CTR only provide confidentiality. An attacker can flip bits in a CTR ciphertext and the matching plaintext bits flip without anyone noticing. GCM is authenticated encryption: it encrypts in counter mode and also computes a 16-byte tag over the ciphertext. Decryption checks the tag first and refuses to release any plaintext if it does not match. This is the "encrypt then MAC" idea from the authenticated-encryption slides in Lecture 7, built into one mode.
- *What I took from it:* The tag is what turns "nobody can read this" into "nobody can change this without being caught". Encryption alone does not give integrity.
- *Changed anything?* No.

**Q2. If one byte of `hello.txt.enc` is changed and sent to `decrypt`, what happens?**
- *Claude's answer (summary):* The server's AES-GCM decryption recomputes the tag over the changed ciphertext, it does not match the stored tag, and the library raises an exception (`InvalidTag` in Python). The server turns that into its one generic `error` reply. No plaintext is returned, not even the parts that were unchanged, because GCM verifies before it decrypts anything for the caller.
- *What I took from it:* This is why a tampered `.enc` gives an error rather than slightly wrong output, and why the server lists "a file that was modified or corrupted" among its error causes.
- *Changed anything?* No, but it confirmed answer A1: the client cannot tell this case apart from a wrong key, so the error message must not guess.

**Q3. How likely is a repeated 12-byte nonce, and what would it leak?**
- *Claude's answer (summary):* A 12-byte nonce has 2^96 values. By the birthday bound, the chance of any repeat among n files with the same key is about n² / 2^97. For a million files that is roughly 2^40 / 2^97 = 2^-57, which is negligible. If it did happen, both files would be encrypted with the same keystream, so XOR-ing the two ciphertexts gives the XOR of the two plaintexts. Worse, it leaks enough about GCM's internal authentication key to let an attacker forge tags.
- *What I took from it:* The nonce must be fresh for every file even though the key can be reused, which is why `encrypt_bytes` draws a new random nonce every time and the fixed nonce exists only for the test.
- *Changed anything?* No.

### Part B: The course HMAC

**Q4. Walk through the `hello world` vector.**
- *Claude's answer (working), with K = bytes 00 01 02 … 1f:*
  - Ki = K XOR 0x36…36 = `36373435323330313e3f3c3d3a3b383926272425222320212e2f2c2d2a2b2829`
  - Ko = K XOR 0x5c…5c = `5c5d5e5f58595a5b54555657505152534c4d4e4f48494a4b4445464740414243`
  - inner = SHA-256(Ki ‖ "hello world") = `05001c1f5260531db22d744e1629e7450903558c545cdd514bea3f555684deac`
  - HMAC = SHA-256(Ko ‖ inner) = `585c65e6deb8b876ed74222c5964060e707192df8ce9b91b6198de173fbfff2e`
  - All four values match spec section 9.
- *What I took from it:* The inner hash is fed to the outer hash as 32 raw bytes, not as the 64-character hex string. Getting that wrong would give a completely different HMAC.
- *Changed anything?* No.

**Q5. Why not simply SHA-256(K ‖ x)?**
- *Claude's answer (summary):* SHA-256 is a Merkle–Damgård hash: its output is the internal state after the last block. Given SHA-256(K ‖ x) and the length of K ‖ x, an attacker can restart the hash from that state and compute SHA-256(K ‖ x ‖ padding ‖ f) for any extra data f, without knowing K. For example, from the MAC of "amount=10" they could produce a valid MAC for "amount=10…&amount=1000". In the nested form, the attacker only ever sees the outer hash. Extending it gives the hash of Ko ‖ inner ‖ f, but a forgery needs Ko ‖ SHA-256(Ki ‖ x ‖ f), so the attack fails. This is the argument on Lecture 7, slide 23.
- *What I took from it:* The second hash is not decoration. It hides the inner hash state that the length-extension attack depends on.
- *Changed anything?* No.

**Q6. If K were padded to 64 bytes as in RFC 2104, would the server still say VERIFIED?**
- *Claude's answer (working):*
  - Course Ki, first 8 bytes: `3637343532333031`
  - Padded Ki, first 8 bytes: `3637343532333031`
  - The first 32 bytes are identical, because padding only adds zeros after K. The difference is the length: the padded Ki is 64 bytes, and its last 32 bytes are all `0x36`. That changes the input to SHA-256, so the result is the standard HMAC, `411b9a51…`, and the server would answer FAILED.
- *What I took from it:* The professor's change is small on paper but changes every output. This is why the requirements say "no block padding" explicitly and why the tests check that the result is not `411b9a51…`.
- *Changed anything?* No.

**Q7. How much of the HMAC changes when one letter changes, and how likely is a forgery by guessing?**
- *Claude's answer (working), with the section 9 key:*
  - HMAC("hello world") = `585c65e6…3fbfff2e`
  - HMAC("hello worle") = `c46a3eb2…ee4b598d`
  - 146 of the 256 bits differ. On average a good hash flips about half the bits (128) for any change to the input; 146 is within normal variation.
  - A random guess is correct with probability 1 in 2^256.
- *What I took from it:* One changed letter produces an unrelated-looking HMAC, which is why the server answered FAILED for `hello_modified.txt`. Guessing a valid HMAC is not a realistic attack.
- *Changed anything?* No.

### Part C: Design choices

**Q8. Why test against the section 9 vectors before using the real server? (My own question: why did we have a fake server at all?)**
- *Claude's answer (summary):* The vectors are fixed values produced by the instructor's implementation, so matching them proves our framing, AES and HMAC agree with his code before any network is involved. A fake server built from our own code only proves the client agrees with itself: if our HMAC were wrong, the fake server would compute the same wrong value and still say VERIFIED. The fake server was useful only for testing error paths and for working before the real server IP was published.
- *What I took from it:* The vectors test correctness; the fake server only tested plumbing. Once the real server was available, it did that job better, so I removed the fake server.
- *Changed anything?* Yes. The fake server and its tests were removed (see section 3).

**Q9. Why must FAILED look different from a server error?**
- *Claude's answer (summary):* FAILED is a valid answer: the request was well formed, and the HMAC does not match the file, so the file or the HMAC has changed. An error means the request itself was rejected, for example an unknown username or a bad key file, and says nothing about the file. If both looked the same, a user could think a file had been tampered with when they had only mistyped their username, or the reverse.
- *What I took from it:* The two outcomes answer different questions: "is this file authentic?" versus "did my request work at all?". The screenshots `03_hmac_failed.png` and `04_server_error.png` show the difference.
- *Changed anything?* No.

**Q10. Why load the `.key` file at decrypt time instead of the key in memory?**
- *Claude's answer (summary):* The server does not remember keys, and the spec's workflow treats decryption as happening "later", possibly after the program has been restarted or after other files have been encrypted with newer keys. The key in memory is only the most recently fetched one. The `.key` file saved beside each `.enc` is the one that actually encrypted it.
- *What I took from it:* Saving the key with the file is what makes decryption reliable, and it is also why losing or overwriting a `.key` file is serious (answer B6).
- *Changed anything?* No.

---

## 3. Decisions changed during the build

| Change | Reason |
|---|---|
| Network functions (`request_*`) take bytes instead of file paths. | Network code and file handling can then be tested separately. |
| The fake server and its tests were removed. | The real server IP arrived quickly, and it is the true test (Q8). |
| `test_real_server.py` was added before the GUI. | To confirm AES and HMAC against the real server early, as the professor asked. |
| Server error text shortened to "ERROR: Server returned an error (detail)". | Shorter, and the server's detail already shows the error is generic. |
| Key files (`.key`, `.hmackey`) are not committed (reverses F4). | Keys should not be stored in a repository, even for a teaching server. |
