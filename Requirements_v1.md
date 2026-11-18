Crypto Server Client: Requirements (v1)
1. Overview
This is a program to talk to a cloud server running on Amazon Web Services. Messages to and from the cloud server will follow the specification given in crypto_message_spec_v2.md, which is in this folder. Read that file first. Wherever this document and the specification disagree on the wire format, the specification wins.
The program is a desktop client with a simple GUI. It lets the user:
1.	get an AES key from the server,
2.	encrypt a file locally with that key,
3.	send an encrypted file and its key to the server and receive the decrypted file back,
4.	compute an HMAC of a file locally with a key from the server,
5.	send a file, its key, and the HMAC to the server and receive VERIFIED or FAILED.
2. Language and libraries
•	Python 3, with Tkinter for the GUI.
•	Use the Python Cryptography library (pip install cryptography) for AES-256-GCM (AESGCM) and for SHA-256 (hashes.SHA256). This AES code is the same as the server's.
•	Use only the standard library for everything else (socket, struct, json, base64, os, threading).
•	Do not use Python's hmac module or cryptography.hazmat.primitives.hmac anywhere.
•	Keep the code simple and in one file, client.py. Put a short comment at the top of each block, not on every line.
3. Connection settings
•	The user types the server IP, the port (default 8080), and their username into the window.
•	Do not hard-code the IP or the username in the source, and do not write them to any file in the repository.
•	Use one TCP connection per request, as recommended in section 2 of the specification: connect, send one message, read one reply, close.
•	Do the network calls off the Tkinter main thread, so the window does not freeze.
4. User interface
•	At the top: IP, port, and username fields, and a message type dropdown with these operations: Get AES Key, Encrypt, Decrypt, Get HMAC Key, Compute HMAC, Verify HMAC.
•	The lower part of the window changes to show only the inputs for the selected operation.
•	A status area at the bottom shows what happened.
•	Never display or log a key.
•	Keep the UI plain. No styling work beyond what is needed to make it usable.
5. AES operations
5.1 Get AES Key
•	Send get_key. Hold the returned 32-byte key in memory until the user encrypts a file.
•	If the user runs Encrypt without first getting a key, show a message telling them to get a key first.
5.2 Encrypt (local only, no network)
•	The user picks a file to encrypt and chooses where to save the output.
•	Refuse files larger than 1,048,548 bytes before doing anything.
•	Encrypt with AES-256-GCM: a new random 12-byte nonce for every file, no associated data. The saved file is nonce (12) | ciphertext | tag (16).
•	Name the output by adding.enc to the full original name and save the key beside it with .key: 
o	wave.wav → wave.wav.enc and wave.wav.key
•	The .key file contains the key as standard base64 text, the same as on the wire.
5.3 Decrypt (server)
•	The user picks a .enc file. The program loads the matching .key file automatically (same base name). If it is missing, let the user pick the key file.
•	Send decrypt with the key and the encrypted file as the payload.
•	Save the returned bytes as the original name with .dec added before the extension, in the folder the user chooses: 
o	wave.wav.enc → wave.dec.wav
•	After saving, if the original file is still in the same folder, compare the two files byte by byte and report "matches original" or "does not match".
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
•	The server has no separate HMAC key command. Send get_key, the same as 5.1, and hold the key as the HMAC key.
6.3 Compute HMAC (local only, no network)
•	The user picks a file. Refuse files over 1,048,576 bytes.
•	Compute the HMAC as in 6.1 and save beside the file, both as base64 text: 
o	wave.wav → wave.wav.hmac and wave.wav.hmackey
6.4 Verify HMAC (server)
•	The user picks the original file. The program loads the matching .hmac and .hmackey files automatically. If either is missing, let the user pick it.
•	Send verify_hmac with key and hmac in base64 and the file as the payload.
•	Show the result clearly: 
o	VERIFIED → green "HMAC verified by server"
o	FAILED → red "HMAC did not match". This is a valid answer, not an error.
o	An error reply → "The server returned an error. It does not give a reason. Check the username, the key file and the file size." Show this differently from FAILED.
7. Errors
•	Show connection failures, timeouts, and error replies in the status area. Do not crash.
•	Do not try to guess the cause from the server's error, which is deliberately generic.
8. Build order and testing
Build and test in this order. Do not move to the next step until the one before passes.
1.	Message framing and the receive loop, tested against the framing vector in specification section 9.
2.	AES-GCM encrypt, tested against the AES vector in section 9, before any networking.
3.	get_key against the real server.
4.	Encrypt a file, decrypt it through the server, and compare the result byte for byte with the original.
5.	The HMAC function, tested against both HMAC vectors in section 9 (hello world and the empty file). It must not produce 411b9a51..., which is the standard HMAC answer.
6.	verify_hmac against the server: VERIFIED for the correct file, then FAILED after changing one byte of the file.
Write the tests for steps 1, 2, and 5 as a small separate script, test_vectors.py.
9. Outputs for submission
Put every file the lab produces in a Results/ folder at the top of the repository:
•	the original test file and its .enc and .key files
•	the decrypted file returned by the server
•	the .hmac and .hmackey files
•	screenshots of a successful decrypt, a VERIFIED result, and a FAILED result
10. Questions
Before writing any code, list every point in this document or the specification that is unclear or could be read in more than one way, and ask me about each one. Do not guess.
