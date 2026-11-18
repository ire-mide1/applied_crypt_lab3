Crypto Server Client: Requirements (v2)
1. Overview
This is a program to talk to a cloud server running on Amazon Web Services. Messages to and from the cloud server follow the specification in crypto_message_spec_v2.md, which is in this folder. Read that file first. Treat crypto_message_spec_v2.md as the whole specification: v1 is obsolete, and the v1 file name in its section 11 is a leftover. Wherever this document and the specification disagree on the wire format, the specification wins.
The program is a desktop client with a simple GUI. It lets the user:
1.	get an AES key from the server,
2.	encrypt a file locally with that key,
3.	send an encrypted file and its key to the server and receive the decrypted file back,
4.	compute an HMAC of a file locally with a key from the server,
5.	send a file, its key, and the HMAC to the server and receive VERIFIED or FAILED.
2. Language and libraries
•	Python 3.9 or newer, with Tkinter for the GUI. Develop on Windows, but use only cross-platform code (pathlib, no Windows-only calls).
•	Use the Python Cryptography library (pip install cryptography) for AES-256-GCM (AESGCM) and for SHA-256 (hashes.SHA256). It is the only crypto library: do not use hashlib. (The Cryptography library was chosen because it is the same AES library the server uses.)
•	Use only the standard library for everything else (socket, struct, json, base64, os, threading, pathlib, tkinter).
•	Do not use Python's hmac module or cryptography.hazmat.primitives.hmac anywhere.
•	Keep the app in one file, client.py, and keep the code simple. "One file" means one file for the app, not one function. Put a short comment at the top of each block (each function and each main section of the file), not on every line.
•	client.py has GUI-free functions for framing, AES, HMAC and the network calls, and an if __name__ == "__main__": guard, so test_vectors.py can import it without opening a window.
•	The encrypt function takes an optional nonce parameter, used only by test_vectors.py. The GUI never passes it, so real files always get a fresh random nonce.
3. Connection settings
•	The user types the server host, the port (default 8080), and their username into the window. The host field accepts any hostname or IP address and only has to be non-empty.
•	Check locally before connecting: the port is a whole number from 1 to 65535, and the username matches the spec's rule (1–32 characters from A-Z a-z 0-9 _ . -). A failed check gets its own specific message, not the server's generic error.
•	Do not hard-code the IP or the username in the source, and do not write them to any file in the repository.
•	Use one TCP connection per request, as recommended in section 2 of the specification: connect, send one message, read one reply, close.
•	Use a 30-second timeout for both connect and read. No retries.
•	Read and validate any input file before connecting.
•	Do the network calls off the Tkinter main thread, so the window does not freeze. Disable all Run buttons while any operation is running. Local work (encrypt, compute HMAC, file comparison) stays on the main thread, since the files are 1 MiB or less.
•	Message framing: build each header with compact JSON separators (",", ":") and the key order type, username, payload_len, then any extra fields. This matches the section 9 framing vector byte for byte.
4. User interface
•	At the top: host/IP, port, and username fields, and an Operation dropdown with these operations: Get AES Key, Encrypt, Decrypt, Get HMAC Key, Compute HMAC, Verify HMAC. (Encrypt and Compute HMAC are local, so the dropdown is not called "message type".)
•	The lower part of the window changes to show only the inputs for the selected operation. Each file field has a Browse button, and each operation has one Run button. Get AES Key and Get HMAC Key need only the connection fields.
•	A status area at the bottom shows a single line with the latest message:
o	VERIFIED in green
o	FAILED in red
o	server error replies and local failures in black, with the prefix "ERROR:". The prefix makes the difference from FAILED clear without relying on colour.
o	notices that are not errors (for example, the comparison being skipped in 5.3) have no prefix.
•	Never display or log a key. This covers the status area, exception text and tracebacks. Do not include header contents in error messages. Messages such as "AES key received" and "HMAC key received", and file paths, are fine.
•	Keep the UI plain. No styling work beyond what is needed to make it usable.
5. AES operations
5.1 Get AES Key
•	Send get_key. Check that the reply is valid standard base64 and decodes to exactly 32 bytes. If not, show "Server sent an invalid key" and do not store it.
•	Hold the key in memory in the AES key slot. This slot is separate from the HMAC key slot (6.2). Keep it until the user gets a new AES key or closes the program. Reusing one AES key across files is safe here because each file gets a fresh random nonce and its own .key file.
•	If the user runs Encrypt without first getting a key, show a message telling them to get a key first.
5.2 Encrypt (local only, no network)
•	The user picks a file to encrypt. A Save-As dialog then opens with <original name>.enc filled in.
•	Refuse files larger than 1,048,548 bytes before doing anything. An empty file is allowed.
•	Encrypt with AES-256-GCM: a new random 12-byte nonce for every file, no associated data. The saved file is nonce (12) | ciphertext | tag (16).
•	Name the output by adding .enc to the full original name and save the key beside it with .key:
o	wave.wav → wave.wav.enc and wave.wav.key
•	The .key file contains the key as standard base64 text, the same as on the wire, with no trailing newline.
•	Never overwrite silently. The Save-As dialog asks about an existing .enc. Also ask before replacing an existing .key file, even when the .enc does not exist, because losing a .key makes its .enc unrecoverable. A key file is replaced only if the user confirms.
5.3 Decrypt (server)
•	The user picks a .enc file. If it does not end in .enc, refuse with "Please pick a .enc file." Refuse a file over 1,048,576 bytes, or shorter than 28 bytes ("Not a valid encrypted file (too short)"), before connecting.
•	The program loads the matching key file automatically: remove .enc and add .key (wave.wav.enc → wave.wav.key). If it is missing, let the user pick the key file with a plain file picker. Whichever file is used, validate it locally before sending (see section 7). The key in memory is never used here: the .key file saved with the .enc is the right one.
•	Send decrypt with the key and the encrypted file as the payload.
•	Save the returned bytes under the original name with .dec inserted before the last extension only, in the folder the user chooses. Remove .enc first, then insert .dec:
o	wave.wav.enc → wave.dec.wav
o	a.tar.gz.enc → a.tar.dec.gz
o	README.enc → README.dec
o	.bashrc.enc → .bashrc.dec
•	Do not overwrite an existing output file without asking.
•	After saving, look for the original only next to the .enc file (the .enc name with .enc removed). The output folder is not searched. If it is found, compare the two files byte by byte and show one of:
o	"Decrypted file matches the original byte for byte."
o	"Decrypted file does NOT match the original."
o	"Original not found next to the .enc file, comparison skipped." (a notice, not an error)
6. HMAC operations
6.1 The HMAC algorithm
This is not standard HMAC (RFC 2104). Implement it by hand with SHA-256 only.
Let K be the 32-byte key from the server and x be the raw bytes of the file.
1.	Inner key: Ki = K XOR (0x36 repeated 32 times)
2.	Outer key: Ko = K XOR (0x5C repeated 32 times)
3.	Do not pad K to the 64-byte SHA-256 block size, and do not hash K first. Ki and Ko are 32 bytes, the same length as K.
4.	Inner hash: h = SHA-256(Ki || x), with Ki first. || is byte concatenation.
5.	Outer hash: HMAC = SHA-256(Ko || h), with Ko first. h is the 32 raw digest bytes, not hex text.
6.	The result is 32 bytes. It is sent and saved as standard base64.
6.2 Get HMAC Key
•	The server has no separate HMAC key command. Send get_key, the same as 5.1, with the same validity check (valid base64, exactly 32 bytes), and hold the key in the HMAC key slot.
•	The AES and HMAC key slots are separate. Getting an HMAC key never replaces the AES key, and the other way round. Keep the HMAC key until the user gets a new one or closes the program.
6.3 Compute HMAC (local only, no network)
•	If there is no HMAC key, show "Get an HMAC key first."
•	The user picks a file. Refuse files over 1,048,576 bytes. An empty file is allowed.
•	Compute the HMAC as in 6.1 and save beside the file, both as base64 text with no trailing newline:
o	wave.wav → wave.wav.hmac and wave.wav.hmackey
•	Ask before replacing an existing .hmac or .hmackey file.
6.4 Verify HMAC (server)
•	The user picks the file to verify. Refuse a file over 1,048,576 bytes before connecting.
•	The program loads the matching .hmac and .hmackey files automatically (file name plus .hmac / .hmackey). If either is missing, let the user pick it with a plain file picker.
•	Validate both files locally before sending (see section 7).
•	Send verify_hmac with key and hmac in base64 and the file as the payload.
•	Show the result clearly:
o	VERIFIED → green "HMAC verified by server"
o	FAILED → red "HMAC did not match". This is a valid answer, not an error.
o	An error reply → black, starting "ERROR: The server returned an error. The server does not say why." followed by the server's detail text. Do not suggest causes. This must look different from FAILED.
7. Errors and local validation
•	Show connection failures, timeouts, and error replies in the status area. Do not crash.
•	Do not try to guess the cause from the server's error, which is deliberately generic. Use the neutral message in 6.4, followed by the server's detail text, for every error reply (get_key, decrypt and verify_hmac).
•	Check everything the client can check before sending, and give each failure its own specific message: file size limits (5.2, 5.3, 6.3, 6.4), the .enc suffix and minimum size (5.3), the port and username format (section 3), and the contents of every key or HMAC file loaded.
•	Key and HMAC file check: strip leading and trailing whitespace when reading, so files written by other clients or edited in Notepad still work. Then require strict standard base64 that decodes to exactly 32 bytes. If the check fails, name the file and the problem.
•	Reply checks: cap the reply header at 1,000 bytes and the reply payload_len at 1,048,576.
o	Invalid JSON, an unexpected reply type, or a value over a cap: "Unexpected reply from server."
o	Connection closed mid-reply: "Connection closed before the full reply arrived."
o	Do not try to recover from either.
8. Build order and testing
Build and test in this order. Do not move to the next step until the one before passes.
1.	Message framing and the receive loop, tested against the framing vector in specification section 9.
2.	AES-GCM encrypt, tested against the AES vector in section 9, before any networking.
3.	The HMAC function, tested against both HMAC vectors in section 9 (hello world and the empty file). It must not produce 411b9a51..., which is the standard HMAC answer.
4.	The network functions in client.py.
5.	Real-server checks, run by the user (the assistant has no access to the server, IP or username), who reports the results back. "Do not move on until it passes" applies when the user reports:
a.	get_key against the real server.
b.	Encrypt a file, decrypt it through the server, and compare the result byte for byte with the original.
c.	verify_hmac against the server: VERIFIED for the correct file, then FAILED after changing one byte of the file.
6.	The GUI, built last, after test_vectors.py passes and the functions work against the real server.
Write the tests for steps 1, 2 and 3 as a small separate script, test_vectors.py. Use plain asserts and print a PASS line for each check. Check:
•	the framing hex
•	AES encrypt against the vector (with the fixed nonce), plus decrypting that vector locally
•	Ki, Ko, the inner hash, the hello world HMAC and the empty-file HMAC
•	that the result is not the standard-HMAC value 411b9a51…
9. Outputs for submission
Put every file the lab produces in a Results/ folder at the top of the repository. Run the program on the test files inside Results/, so every output lands there and each original sits beside its .enc.
Test files:
•	hello.txt, containing exactly "hello world" (11 bytes, no newline), to match the section 9 vectors
•	one small binary file under 1 MiB, such as a .wav or .png
Outputs:
•	each original test file and its .enc and .key files
•	the decrypted file returned by the server
•	the .hmac and .hmackey files
•	hello_modified.txt: a copy of hello.txt with one byte changed. Verify it with the original's hello.txt.hmac and hello.txt.hmackey, picked by hand. The original stays untouched.
•	screenshots, taken by the user, named:
o	01_decrypt_success.png
o	02_hmac_verified.png
o	03_hmac_failed.png
•	Mask or crop the IP and username fields in every screenshot, because the screenshots are committed.
Keys (.key and .hmackey) are committed. They are random keys for a teaching server, and the grader needs them to check the decrypt and the HMAC. The .gitignore excludes only __pycache__/ and *.pyc.
10. Open questions
All questions from the v1 review have been answered and are written into the sections above. If anything is still unclear while coding, ask rather than guess.
