from Crypto.Cipher import Salsa20

def decrypt(nonce, key, ciphertext):
    """
    Attempts to decrypt the ciphertext using Salsa20 and returns the result.

    Args:
        nonce (bytes): Nonce (8 bytes for Salsa20).
        key (bytes): Encryption key (16 or 32 bytes).
        ciphertext (bytes): Ciphertext to decrypt.

    Returns:
        list: A list containing a single tuple ('Salsa20', plaintext) if successful.
              Returns an empty list if the key or nonce is invalid.
    """
    # Validate key length: Salsa20 requires 16 or 32 bytes (128 or 256 bits)
    if len(key) not in [16, 32]:
        return []

    # Try with the standard 8-byte nonce
    if len(nonce) == 8:
        try:
            # Create Salsa20 cipher object with key and nonce
            cipher = Salsa20.new(key=key, nonce=nonce)
            plaintext = cipher.decrypt(ciphertext)
            
            # Basic validation - check if result might be text
            try:
                plaintext.decode('utf-8')
                return [('Salsa20', plaintext)]
            except UnicodeDecodeError:
                # If it's not UTF-8 text, we still return the result
                return [('Salsa20', plaintext)]
        except (ValueError, KeyError):
            pass  # Fall through to try other formats
            
    # Some implementations may prefix the nonce to the ciphertext
    # Try with potential 8-byte nonce prepended to ciphertext
    if len(ciphertext) > 8:
        potential_nonce = ciphertext[:8]
        remaining_ciphertext = ciphertext[8:]
        
        try:
            cipher = Salsa20.new(key=key, nonce=potential_nonce)
            plaintext = cipher.decrypt(remaining_ciphertext)
            
            # Check if result might be text
            try:
                plaintext.decode('utf-8')
                return [('Salsa20-PrependedNonce', plaintext)]
            except UnicodeDecodeError:
                # If it's not UTF-8 text, we still return the result
                return [('Salsa20-PrependedNonce', plaintext)]
        except (ValueError, KeyError):
            pass
    
    # If we reach here, all decryption attempts failed
    return [] 