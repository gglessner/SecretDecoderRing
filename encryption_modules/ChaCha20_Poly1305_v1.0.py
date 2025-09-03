from Crypto.Cipher import ChaCha20_Poly1305

def decrypt(nonce, key, ciphertext):
    """
    Attempts to decrypt the ciphertext using ChaCha20-Poly1305 AEAD mode and returns the result.
    For this AEAD mode, the ciphertext must include the authentication tag.

    Args:
        nonce (bytes): Nonce (should be 12 bytes for ChaCha20-Poly1305).
        key (bytes): Encryption key (32 bytes).
        ciphertext (bytes): Ciphertext to decrypt, with authentication tag at the end.

    Returns:
        list: A list containing a single tuple ('ChaCha20-Poly1305', plaintext) if successful.
              Returns an empty list if decryption fails.
    """
    # Validate key length: ChaCha20-Poly1305 requires 32 bytes (256 bits)
    if len(key) != 32:
        return []

    # Validate nonce length: ChaCha20-Poly1305 requires 12 bytes (96 bits)
    if len(nonce) != 12:
        return []

    # The ciphertext must be at least 16 bytes (for the authentication tag)
    if len(ciphertext) < 16:
        return []

    # Try with the standard format (ciphertext + tag)
    try:
        # For ChaCha20-Poly1305, we assume the last 16 bytes are the tag
        tag = ciphertext[-16:]
        actual_ciphertext = ciphertext[:-16]
        
        # Create cipher object
        cipher = ChaCha20_Poly1305.new(key=key, nonce=nonce)
        
        # Attempt to decrypt and verify
        plaintext = cipher.decrypt_and_verify(actual_ciphertext, tag)
        
        # Basic validation - check if result might be text
        try:
            plaintext.decode('utf-8')
            return [('ChaCha20-Poly1305', plaintext)]
        except UnicodeDecodeError:
            # If it's not UTF-8 text, we still return the result
            return [('ChaCha20-Poly1305', plaintext)]
    except (ValueError, KeyError):
        pass
    
    # Try to decrypt with all possible tag positions (sliding window)
    # This helps if the tag is located elsewhere or if additional data is present
    min_ct_size = 1  # Minimum ciphertext size to attempt
    if len(ciphertext) > min_ct_size + 16:
        for i in range(len(ciphertext) - 16):
            try:
                actual_ciphertext = ciphertext[:i] + ciphertext[i+16:]
                tag = ciphertext[i:i+16]
                
                cipher = ChaCha20_Poly1305.new(key=key, nonce=nonce)
                plaintext = cipher.decrypt_and_verify(actual_ciphertext, tag)
                
                try:
                    plaintext.decode('utf-8')
                    return [('ChaCha20-Poly1305-AltTag', plaintext)]
                except UnicodeDecodeError:
                    return [('ChaCha20-Poly1305-AltTag', plaintext)]
            except (ValueError, KeyError):
                continue
    
    # If we reach here, all decryption attempts failed
    return [] 