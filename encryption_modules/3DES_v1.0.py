from Crypto.Cipher import DES3

def decrypt(iv, key, ciphertext):
    """
    Decrypt ciphertext using Triple DES with various modes.

    Args:
        iv (bytes): Initialization vector (not used for ECB mode)
        key (bytes): Encryption key
        ciphertext (bytes): Data to decrypt

    Returns:
        list: List of tuples (mode_name, plaintext) for successful decryptions
    """
    block_size = 8
    results = []
    modes = [
        ("MODE_ECB", DES3.MODE_ECB, None),
        ("MODE_CBC", DES3.MODE_CBC, iv),
        ("MODE_CFB", DES3.MODE_CFB, iv),
        ("MODE_OFB", DES3.MODE_OFB, iv),
    ]

    for mode_name, mode, mode_iv in modes:
        try:
            if mode == DES3.MODE_ECB:
                # ECB mode does not use an IV
                cipher = DES3.new(key, mode)
            else:
                # Other modes require an IV
                if mode_iv is None:
                    continue
                cipher = DES3.new(key, mode, mode_iv)

            # Decrypt and unpad for non-CTR modes
            plaintext_padded = cipher.decrypt(ciphertext)
            if mode != DES3.MODE_OFB:  # OFB doesn't use padding
                plaintext = unpad(plaintext_padded, block_size)
            else:
                plaintext = plaintext_padded
            results.append((mode_name, plaintext))
        except ValueError:
            continue

    return results

def unpad(data, block_size):
    """
    Remove PKCS#5/PKCS#7 padding from data.

    Args:
        data (bytes): Padded data
        block_size (int): Block size in bytes

    Returns:
        bytes: Unpadded data
    """
    if not data or len(data) % block_size != 0:
        return data
    padding_len = data[-1]
    if padding_len > block_size:
        return data
    return data[:-padding_len]
