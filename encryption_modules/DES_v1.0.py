from Crypto.Cipher import DES

def decrypt(iv, key, ciphertext):
    """
    Attempts to decrypt the ciphertext using DES and returns the result.
    Implements ECB and CBC modes.

    Args:
        iv (bytes): Initialization vector for CBC mode (8 bytes).
        key (bytes): Encryption key (8 bytes).
        ciphertext (bytes): Ciphertext to decrypt.

    Returns:
        list: A list of tuples (mode_name, plaintext) for each successful decryption.
              Returns an empty list if no mode succeeds.
    """
    results = []

    # DES uses a key size of 8 bytes (64 bits, although only 56 bits are effective)
    if len(key) != 8:
        return results

    # The ciphertext must be a multiple of the block size (8 bytes)
    if len(ciphertext) % 8 != 0 or len(ciphertext) < 8:
        return results

    def is_valid_padding(padded_data):
        """Check if PKCS#7 padding is valid"""
        pad_len = padded_data[-1]
        # Validate padding length
        if pad_len < 1 or pad_len > 8:
            return False
        # Check all padding bytes are correct
        return padded_data[-pad_len:] == bytes([pad_len]) * pad_len

    def try_utf8(data):
        """Check if data can be decoded as UTF-8"""
        try:
            data.decode('utf-8')
            return True
        except UnicodeDecodeError:
            return False

    # Try ECB mode (no IV needed)
    try:
        cipher = DES.new(key, DES.MODE_ECB)
        pt_padded = cipher.decrypt(ciphertext)
        
        if is_valid_padding(pt_padded):
            # Remove PKCS#7 padding
            pad_len = pt_padded[-1]
            pt = pt_padded[:-pad_len]
            
            if try_utf8(pt):
                results.append(('DES-ECB', pt))
    except Exception:
        pass

    # Try CBC mode (requires valid IV)
    if iv and len(iv) == 8:
        try:
            cipher = DES.new(key, DES.MODE_CBC, iv)
            pt_padded = cipher.decrypt(ciphertext)
            
            if is_valid_padding(pt_padded):
                # Remove PKCS#7 padding
                pad_len = pt_padded[-1]
                pt = pt_padded[:-pad_len]
                
                if try_utf8(pt):
                    results.append(('DES-CBC', pt))
        except Exception:
            pass

    # Handle potential prepended IV (common in CBC mode)
    if len(ciphertext) > 8:
        potential_iv = ciphertext[:8]
        remaining_ciphertext = ciphertext[8:]
        
        if len(remaining_ciphertext) % 8 == 0:
            try:
                cipher = DES.new(key, DES.MODE_CBC, potential_iv)
                pt_padded = cipher.decrypt(remaining_ciphertext)
                
                if is_valid_padding(pt_padded):
                    # Remove PKCS#7 padding
                    pad_len = pt_padded[-1]
                    pt = pt_padded[:-pad_len]
                    
                    if try_utf8(pt):
                        results.append(('DES-CBC-PrependedIV', pt))
            except Exception:
                pass

    return results 