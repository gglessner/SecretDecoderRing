from Crypto.Cipher import ARC4

def decrypt(iv, key, ciphertext):
    """
    Attempts to decrypt the ciphertext using RC4 and returns the result.
    Note: RC4 does not use an IV/nonce in its traditional implementation.

    Args:
        iv (bytes): Ignored for RC4 (this cipher does not use an IV).
        key (bytes): Encryption key (typically 5-16 bytes, but can be 1-256 bytes).
        ciphertext (bytes): Ciphertext to decrypt.

    Returns:
        list: A list containing a single tuple ('RC4', plaintext) if successful.
              Returns an empty list if the key is invalid or decryption fails.
    """
    # RC4 supports key sizes from 1 to 256 bytes, but practical
    # implementations typically use 5-16 bytes for security
    if len(key) < 1 or len(key) > 256:
        return []

    try:
        # Create RC4 cipher object with key
        cipher = ARC4.new(key)
        plaintext = cipher.decrypt(ciphertext)
        
        # Basic validation - check if result might be text
        try:
            plaintext.decode('utf-8')
            return [('RC4', plaintext)]
        except UnicodeDecodeError:
            # If it's not UTF-8 text, we still return the result
            # as the caller will handle this case
            return [('RC4', plaintext)]
    except (ValueError, KeyError):
        # Return empty list if decryption fails
        return [] 