# See shorter.py for versions of these two functions with a minimum of
# intermediate variables; shorter, but not so good for understanding
# what's going on.

def hybrid_encrypt(plaintext, asymmetric_key):
    """Encrypt the plaintext, using a randomly generated symmetric key.

    The symmetric key is encrypted with the given asymmetric_key, and
    that encrypted key is returned, with the encrypted input appended.
    """
    symmetric_key = Random.new().read(32)
    initialization_vector = Random.new().read(AES.block_size)
    cipher = AES.new(symmetric_key, AES.MODE_CFB, initialization_vector)
    symmetrically_encrypted_payload = (initialization_vector
                                       + cipher.encrypt(plaintext))
    asymmetrically_encrypted_symmetric_iv_and_key = (
        asymmetric_key.publickey().encrypt(
            initialization_vector + symmetric_key, 32)[0])
    return (asymmetrically_encrypted_symmetric_iv_and_key
            + symmetrically_encrypted_payload)

def hybrid_decrypt(ciphertext, asymmetric_key):
    """Use the asymmetric key to decrypt a symmetric key.

    The asymmetric key is at the start of the ciphertext.  That key is
    then used to decrypt the rest of the ciphertext.
    """
    asymmetrically_encrypted_symmetric_iv_and_key = ciphertext[:128]
    symmetrically_encrypted_payload = ciphertext[128:]
    symmetric_key_and_iv = asymmetric_key.decrypt(
        asymmetrically_encrypted_symmetric_iv_and_key)[:48]
    initialization_vector = symmetric_key_and_iv[:AES.block_size]
    symmetric_key = symmetric_key_and_iv[AES.block_size:]
    cipher = AES.new(symmetric_key, AES.MODE_CFB, initialization_vector)
    decrypted_data = cipher.decrypt(symmetrically_encrypted_payload)
    return decrypted_data[16:]
