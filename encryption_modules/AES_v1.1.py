from Crypto.Cipher import AES
from Crypto.Util import Counter

def decrypt(iv, key, ciphertext):
    """
    Decrypts ciphertext using all AES modes, trying both provided IV and prepended IVs.
    
    Args:
        iv (bytes): Initialization vector provided separately.
        key (bytes): AES key (16, 24, or 32 bytes).
        ciphertext (bytes): Data to decrypt, possibly including prepended IV and/or tag.
    
    Returns:
        list: Tuples of (mode_description, plaintext) for each successful decryption.
    """
    results = []
    if len(key) not in [16, 24, 32]:
        return results

    # Define modes with their properties: (mode, try_provided_iv, prepended_iv_lengths)
    modes = [
        ('ECB', AES.MODE_ECB, False, []),
        ('CBC', AES.MODE_CBC, len(iv) == 16, [16]),
        ('CFB', AES.MODE_CFB, len(iv) == 16, [16]),
        ('OFB', AES.MODE_OFB, len(iv) == 16, [16]),
        ('CTR', AES.MODE_CTR, True, [8, 12, 16]),
        ('GCM', AES.MODE_GCM, True, [12, 16]),
        ('EAX', AES.MODE_EAX, True, [12, 16]),
    ]

    def try_decrypt_padded(cipher, data, mode_name, desc):
        """Helper to decrypt and unpad data for modes with padding."""
        plaintext_padded = cipher.decrypt(data)
        pad_len = plaintext_padded[-1]
        if 1 <= pad_len <= 16 and plaintext_padded[-pad_len:] == bytes([pad_len]) * pad_len:
            return (f"{mode_name} ({desc})", plaintext_padded[:-pad_len])
        return None

    def try_decrypt_with_tag(cipher, data, tag, mode_name, desc):
        """Helper to decrypt and verify data for modes with authentication tags."""
        plaintext = cipher.decrypt_and_verify(data, tag)
        return (f"{mode_name} ({desc})", plaintext)

    for mode_name, mode, try_provided_iv, iv_lengths in modes:
        # Attempt decryption with provided IV
        if try_provided_iv:
            try:
                if mode in [AES.MODE_CBC, AES.MODE_CFB, AES.MODE_OFB]:
                    if len(ciphertext) % 16 == 0 and len(ciphertext) >= 16:
                        cipher = AES.new(key, mode, iv=iv)
                        result = try_decrypt_padded(cipher, ciphertext, mode_name, "provided IV")
                        if result:
                            results.append(result)
                elif mode == AES.MODE_CTR:
                    ctr = Counter.new(128, initial_value=int.from_bytes(iv, 'big'))
                    cipher = AES.new(key, mode, counter=ctr)
                    plaintext = cipher.decrypt(ciphertext)
                    results.append((f"{mode_name} (provided IV)", plaintext))
                elif mode in [AES.MODE_GCM, AES.MODE_EAX]:
                    if len(ciphertext) >= 16:
                        tag = ciphertext[-16:]
                        data = ciphertext[:-16]
                        cipher = AES.new(key, mode, nonce=iv)
                        result = try_decrypt_with_tag(cipher, data, tag, mode_name, "provided IV")
                        if result:
                            results.append(result)
            except (ValueError, KeyError, TypeError):
                pass

        # Attempt decryption with prepended IVs
        for iv_len in iv_lengths:
            if len(ciphertext) < iv_len + 16:  # Ensure enough length for IV + data
                continue
            mode_iv = ciphertext[:iv_len]
            try:
                if mode in [AES.MODE_CBC, AES.MODE_CFB, AES.MODE_OFB]:
                    data = ciphertext[iv_len:]
                    if len(data) % 16 == 0 and len(data) >= 16:
                        cipher = AES.new(key, mode, iv=mode_iv)
                        result = try_decrypt_padded(cipher, data, mode_name, f"prepended IV len={iv_len}")
                        if result:
                            results.append(result)
                elif mode == AES.MODE_CTR:
                    data = ciphertext[iv_len:]
                    ctr = Counter.new(128, initial_value=int.from_bytes(mode_iv, 'big'))
                    cipher = AES.new(key, mode, counter=ctr)
                    plaintext = cipher.decrypt(data)
                    results.append((f"{mode_name} (prepended IV len={iv_len})", plaintext))
                elif mode in [AES.MODE_GCM, AES.MODE_EAX]:
                    tag = ciphertext[-16:]
                    data = ciphertext[iv_len:-16]
                    cipher = AES.new(key, mode, nonce=mode_iv)
                    result = try_decrypt_with_tag(cipher, data, tag, mode_name, f"prepended IV len={iv_len}")
                    if result:
                        results.append(result)
            except (ValueError, KeyError, TypeError):
                pass

        # Handle ECB separately (no IV)
        if mode == AES.MODE_ECB:
            try:
                if len(ciphertext) % 16 == 0 and len(ciphertext) >= 16:
                    cipher = AES.new(key, mode)
                    result = try_decrypt_padded(cipher, ciphertext, mode_name, "")
                    if result:
                        results.append((mode_name, result[1]))  # Drop empty desc
            except (ValueError, KeyError, TypeError):
                pass

    return results
