# -----------------------------------------------------------------------------
# Added by liupenghui, based on Gmssl LIB
# -----------------------------------------------------------------------------
import sys
from ndn.security.sm4 import CryptSM4, SM4_ENCRYPT, SM4_DECRYPT, crypt_ofb_encrypt, crypt_ofb_decrypt,crypt_cfb_encrypt, crypt_cfb_decrypt

key = b'3l5butlj26hvv313'
value = b'111'
iv = b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
crypt_sm4 = CryptSM4()

crypt_sm4.set_key(key, SM4_ENCRYPT)
encrypt_value = crypt_sm4.crypt_ecb(value)
crypt_sm4.set_key(key, SM4_DECRYPT)
decrypt_value = crypt_sm4.crypt_ecb(encrypt_value)
assert value == decrypt_value
print("sm4 crypt_ecb OK!")

crypt_sm4.set_key(key, SM4_ENCRYPT)
encrypt_value = crypt_sm4.crypt_cbc(iv , value)
crypt_sm4.set_key(key, SM4_DECRYPT)
decrypt_value = crypt_sm4.crypt_cbc(iv , encrypt_value)
assert value == decrypt_value
print("sm4 crypt_cbc OK!")

key = b'3l5butlj26hvv313'
iv =  b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
M =  b'111111111111111111111111111111111111'
C = crypt_ofb_encrypt(key, iv, M)
decrypt_M = crypt_ofb_decrypt(key, iv, C)
assert M == decrypt_M
print("sm4 crypt_ofb OK!")

C = crypt_cfb_encrypt(key, iv, M)
decrypt_M = crypt_cfb_decrypt(key, iv, C)
assert M == decrypt_M
print("sm4 crypt_cfb OK!")

