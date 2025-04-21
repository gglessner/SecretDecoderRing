SecretDecoderRing - Modular Multi-Algorithm Decryption Tool For Penetration Testers
===================================================================================

This Python script is designed for penetration testers to decrypt encrypted passwords or data when encryption keys are discovered, without prior knowledge of the encryption algorithm or mode. It supports multiple encryption algorithms by dynamically loading modules from an `encryption_modules` directory and attempts decryption with each module using provided initialization vector (IV)/nonce, key, and ciphertext inputs.

Features
--------
- User-Friendly Interface: Supports interactive mode with clear prompts and error messages for manual use.
- Flexible Input Handling: Accepts IV, key, and ciphertext as strings, hex (with `0x` prefix), or base64-encoded data.
- Dynamic Module Loading: Automatically loads decryption modules from the `encryption_modules` directory, allowing easy extension with new algorithms.
- Multiple Algorithm Support: Attempts decryption with all loaded modules, supporting various algorithms (e.g., AES, 3DES, Blowfish, CAST5, ChaCha20) and modes.
- Batch Processing: Decrypts multiple ciphertexts from a file using the `--batch` option, processing each line as a separate ciphertext.
- UTF-8 Validation: Only outputs plaintext that is valid UTF-8, avoiding garbage data.
- Quiet Mode: Suppresses non-essential output with `--quiet`, printing only successful decryption results and UTF-8 notes for scripting or automation.
- Debug Mode: Optional debug output for troubleshooting input processing.

Requirements
------------
- Python 3.6+
- Encryption libraries (e.g., `pycryptodome` for AES, ChaCha20, etc.) as required by the loaded modules.
- Directory `encryption_modules` containing Python modules with a `decrypt` function.

Examples
--------
- Interactive mode:\
\
```./SecretDecoderRing.py```

- Batch mode with null IV and Key:\
\
```python SecretDecoderRing.py --batch ciphertexts.txt --null-iv --key LW5BQkNERUZHSElKS0xNTk9QCg==```

- Single ciphertext with quiet mode:\
\
```./SecretDecoderRing.py --ciphertext TXlzZWNyZXRwYXNzd29yZAo= --null-iv --key AAAAAAAAAAAAAAAA --quiet```
