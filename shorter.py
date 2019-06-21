# These are shorter versions (minimum intermediate variables) of
# functions in client_server.py.  See the originals to get names for
# the stages of each computation.

def hybrid_encrypt(plaintext, asymmetric_key):
    """Encrypt the plaintext, using a randomly generated symmetric key.

    The symmetric key is encrypted with the given asymmetric_key, and
    that encrypted key is returned, with the encrypted input appended.
    """
    symmetric_key = Random.new().read(32)
    initialization_vector = Random.new().read(AES.block_size)
    return ((asymmetric_key.publickey().encrypt(
        initialization_vector + symmetric_key, 32)[0])
            + (initialization_vector
               + AES.new(symmetric_key,
                         AES.MODE_CFB,
                         initialization_vector).encrypt(plaintext)))

def hybrid_decrypt(ciphertext, asymmetric_key):
    """Use the asymmetric key to decrypt a symmetric key.

    The asymmetric key is at the start of the ciphertext.  That key is
    then used to decrypt the rest of the ciphertext.
    """
    symmetric_key_and_iv = asymmetric_key.decrypt(
        ciphertext[:128])[:48]
    return AES.new(symmetric_key_and_iv[AES.block_size:],
                   AES.MODE_CFB,
                   symmetric_key_and_iv[:AES.block_size]).decrypt(ciphertext[128:])[16:].decode()
