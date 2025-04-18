from Crypto.Cipher import ChaCha20

def decrypt(nonce, key, ciphertext):
    """
    Attempts to decrypt the ciphertext using ChaCha20 and returns the result.

    Args:
        nonce (bytes): Nonce (typically 12 bytes for ChaCha20).
        key (bytes): Encryption key (32 bytes).
        ciphertext (bytes): Ciphertext to decrypt.

    Returns:
        list: A list containing a single tuple ('ChaCha20', plaintext) if successful.
              Returns an empty list if the key or nonce is invalid.
    """
    # Validate key length: ChaCha20 requires 32 bytes (256 bits)
    if len(key) != 32:
        return []

    # Validate nonce length: ChaCha20 typically uses 12 bytes (96 bits)
    if len(nonce) != 12:
        return []

    try:
        # Create ChaCha20 cipher object with key and nonce
        cipher = ChaCha20.new(key=key, nonce=nonce)
        plaintext = cipher.decrypt(ciphertext)
        return [('ChaCha20', plaintext)]
    except (ValueError, KeyError):
        # Return empty list if decryption fails (e.g., malformed ciphertext)
        return []
