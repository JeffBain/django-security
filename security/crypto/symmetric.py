# Copyright (c) 2011, SD Elements. See ../../LICENSE.txt for details.

from Crypto.Random import get_random_bytes
from Crypto.Cipher import AES


# Encrypt and decrypt binary data with AES. Because the length of the plaintext
# must be a multiple of the AES block size (16 bytes), we prefix at least one
# byte of padding (a hexadecimal digit counting the number of additional bytes
# of padding) before we encrypt.

def encrypt(binary_plaintext, key):
    padding_length = 16 - ((len(binary_plaintext) + 1) % 16 or 16)
    return AES.new(key).encrypt("%x" % padding_length + " " * padding_length +
                                  binary_plaintext)

def decrypt(binary_ciphertext, key):
    plaintext = AES.new(key).decrypt(binary_ciphertext)
    return plaintext[1 + int(plaintext[0], 16):]

def key():
    # The maximum AES key length. 16 and 24 would also have been legal.
    return get_random_bytes(32)

