from Crypto.Cipher import Blowfish

def decrypt(iv, key, ciphertext):
    """
    Decrypt ciphertext using Blowfish with various modes.

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
        ("MODE_ECB", Blowfish.MODE_ECB, None),
        ("MODE_CBC", Blowfish.MODE_CBC, iv),
        ("MODE_CFB", Blowfish.MODE_CFB, iv),
        ("MODE_OFB", Blowfish.MODE_OFB, iv),
    ]

    for mode_name, mode, mode_iv in modes:
        try:
            if mode == Blowfish.MODE_ECB:
                # ECB mode does not use an IV
                cipher = Blowfish.new(key, mode)
            else:
                # Other modes require an IV
                if mode_iv is None:
                    continue
                cipher = Blowfish.new(key, mode, mode_iv)

            # Decrypt and unpad for non-CTR modes
            plaintext_padded = cipher.decrypt(ciphertext)
            if mode != Blowfish.MODE_OFB:  # OFB doesn't use padding
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
