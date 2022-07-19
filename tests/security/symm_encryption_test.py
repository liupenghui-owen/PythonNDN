# -----------------------------------------------------------------------------
# Copyright (C) 2019-2020 The python-ndn authors
#
# Created by liupenghui, Show how to encrypt/decrypt a byte message using symmetric algorithms excluding SM4.  
# 
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
# -----------------------------------------------------------------------------
import asyncio as aio
import sys
import os
import unittest
from binascii import unhexlify
from Cryptodome.SelfTest.loader import load_test_vectors
from Cryptodome.SelfTest.st_common import list_test_cases
from Cryptodome.Util.py3compat import tobytes, is_string
from Cryptodome.Cipher import AES, DES3, DES
from Cryptodome.Hash import SHAKE128, SHA256
from ndn.security.symm_algs import AES_128_CBC_ENC,AES_128_CBC_DEC,AES_192_CBC_ENC,AES_192_CBC_DEC,AES_256_CBC_ENC,AES_256_CBC_DEC,\
                                   AES_128_ECB_ENC,AES_128_ECB_DEC,AES_192_ECB_ENC,AES_192_ECB_DEC,AES_256_ECB_ENC,AES_256_ECB_DEC,\
                                   AES_128_CFB_ENC,AES_128_CFB_DEC,AES_192_CFB_ENC,AES_192_CFB_DEC,AES_256_CFB_ENC,AES_256_CFB_DEC,\
                                   AES_128_OFB_ENC,AES_128_OFB_DEC,AES_192_OFB_ENC,AES_192_OFB_DEC,AES_256_OFB_ENC,AES_256_OFB_DEC

class AES_CBC_TestVectors(unittest.TestCase):
    def test_aes_128(self):
        key =           '2b7e151628aed2a6abf7158809cf4f3c'
        iv =            '000102030405060708090a0b0c0d0e0f'
        plaintext =     '6bc1bee22e409f96e93d7e117393172a' +\
                        'ae2d8a571e03ac9c9eb76fac45af8e51' +\
                        '30c81c46a35ce411e5fbc1191a0a52ef' +\
                        'f69f2445df4f9b17ad2b417be66c3710'
        ciphertext =    '7649abac8119b246cee98e9b12e9197d' +\
                        '5086cb9b507219ee95db113a917678b2' +\
                        '73bed6b8e3c1743b7116e69e22229516' +\
                        '3ff1caa1681fac09120eca307586e1a7'

        key = unhexlify(key)
        iv = unhexlify(iv)
        plaintext = unhexlify(plaintext)
        ciphertext = unhexlify(ciphertext)

        cipher = AES.new(key, AES.MODE_CBC, iv)
        self.assertEqual(cipher.encrypt(plaintext), ciphertext)
        cipher = AES.new(key, AES.MODE_CBC, iv)
        self.assertEqual(cipher.decrypt(ciphertext), plaintext)

    def test_aes_192(self):
        key =           '8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b'
        iv =            '000102030405060708090a0b0c0d0e0f'
        plaintext =     '6bc1bee22e409f96e93d7e117393172a' +\
                        'ae2d8a571e03ac9c9eb76fac45af8e51' +\
                        '30c81c46a35ce411e5fbc1191a0a52ef' +\
                        'f69f2445df4f9b17ad2b417be66c3710'
        ciphertext =    '4f021db243bc633d7178183a9fa071e8' +\
                        'b4d9ada9ad7dedf4e5e738763f69145a' +\
                        '571b242012fb7ae07fa9baac3df102e0' +\
                        '08b0e27988598881d920a9e64f5615cd'

        key = unhexlify(key)
        iv = unhexlify(iv)
        plaintext = unhexlify(plaintext)
        ciphertext = unhexlify(ciphertext)

        cipher = AES.new(key, AES.MODE_CBC, iv)
        self.assertEqual(cipher.encrypt(plaintext), ciphertext)
        cipher = AES.new(key, AES.MODE_CBC, iv)
        self.assertEqual(cipher.decrypt(ciphertext), plaintext)

    def test_aes_256(self):
        key =           '603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4'
        iv =            '000102030405060708090a0b0c0d0e0f'
        plaintext =     '6bc1bee22e409f96e93d7e117393172a' +\
                        'ae2d8a571e03ac9c9eb76fac45af8e51' +\
                        '30c81c46a35ce411e5fbc1191a0a52ef' +\
                        'f69f2445df4f9b17ad2b417be66c3710'
        ciphertext =    'f58c4c04d6e5f1ba779eabfb5f7bfbd6' +\
                        '9cfc4e967edb808d679f777bc6702c7d' +\
                        '39f23369a9d9bacfa530e26304231461' +\
                        'b2eb05e2c39be9fcda6c19078c6a9d1b'

        key = unhexlify(key)
        iv = unhexlify(iv)
        plaintext = unhexlify(plaintext)
        ciphertext = unhexlify(ciphertext)

        cipher = AES.new(key, AES.MODE_CBC, iv)
        self.assertEqual(cipher.encrypt(plaintext), ciphertext)
        cipher = AES.new(key, AES.MODE_CBC, iv)
        self.assertEqual(cipher.decrypt(ciphertext), plaintext)

class AES_ECB_TestVectors(unittest.TestCase):
    def test_aes_128(self):
        key = b'a' * 16
        expected = 'c0b27011eb15bf144d2fc9fae80ea16d4c231cb230416c5fac02e6835ad9d7d0'
        # Run tests without hardware AES-NI instructions.
        cipher = AES.new(key, AES.MODE_ECB, use_aesni = False)
        pt = b"".join([ tobytes('{0:016x}'.format(x)) for x in range(20) ])
        ct = cipher.encrypt(pt)
        self.assertEqual(SHA256.new(ct).hexdigest(), expected)
        self.assertEqual(cipher.decrypt(ct), pt)
        
    def test_aes_192(self):
        key = b'a' * 24
        expected = 'df8435ce361a78c535b41dcb57da952abbf9ee5954dc6fbcd75fd00fa626915d'
        # Run tests without hardware AES-NI instructions.
        cipher = AES.new(key, AES.MODE_ECB, use_aesni = False)
        pt = b"".join([ tobytes('{0:016x}'.format(x)) for x in range(20) ])
        ct = cipher.encrypt(pt)
        self.assertEqual(SHA256.new(ct).hexdigest(), expected)
        self.assertEqual(cipher.decrypt(ct), pt)

    def test_aes_256(self):
        key = b'a' * 32
        expected = '211402de6c80db1f92ba255881178e1f70783b8cfd3b37808205e48b80486cd8'
        # Run tests without hardware AES-NI instructions.
        cipher = AES.new(key, AES.MODE_ECB, use_aesni = False)
        pt = b"".join([ tobytes('{0:016x}'.format(x)) for x in range(20) ])
        ct = cipher.encrypt(pt)
        self.assertEqual(SHA256.new(ct).hexdigest(), expected)
        self.assertEqual(cipher.decrypt(ct), pt)
        
class AES_CFB_TestVectors(unittest.TestCase):
    def test_aes_128(self):
        plaintext =     '6bc1bee22e409f96e93d7e117393172a' +\
                        'ae2d8a571e03ac9c9eb76fac45af8e51' +\
                        '30c81c46a35ce411e5fbc1191a0a52ef' +\
                        'f69f2445df4f9b17ad2b417be66c3710'
        ciphertext =    '3b3fd92eb72dad20333449f8e83cfb4a' +\
                        'c8a64537a0b3a93fcde3cdad9f1ce58b' +\
                        '26751f67a3cbb140b1808cf187a4f4df' +\
                        'c04b05357c5d1c0eeac4c66f9ff7f2e6'
        key =           '2b7e151628aed2a6abf7158809cf4f3c'
        iv =            '000102030405060708090a0b0c0d0e0f'
        key = unhexlify(key)
        iv = unhexlify(iv)
        plaintext = unhexlify(plaintext)
        ciphertext = unhexlify(ciphertext)

        cipher = AES.new(key, AES.MODE_CFB, iv, segment_size=128)
        self.assertEqual(cipher.encrypt(plaintext), ciphertext)
        cipher = AES.new(key, AES.MODE_CFB, iv, segment_size=128)
        self.assertEqual(cipher.decrypt(ciphertext), plaintext)

    def test_aes_192(self):
        plaintext =     '6bc1bee22e409f96e93d7e117393172a' +\
                        'ae2d8a571e03ac9c9eb76fac45af8e51' +\
                        '30c81c46a35ce411e5fbc1191a0a52ef' +\
                        'f69f2445df4f9b17ad2b417be66c3710'
        ciphertext =    'cdc80d6fddf18cab34c25909c99a4174' +\
                        '67ce7f7f81173621961a2b70171d3d7a' +\
                        '2e1e8a1dd59b88b1c8e60fed1efac4c9' +\
                        'c05f9f9ca9834fa042ae8fba584b09ff'
        key =           '8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b'
        iv =            '000102030405060708090a0b0c0d0e0f'
        key = unhexlify(key)
        iv = unhexlify(iv)
        plaintext = unhexlify(plaintext)
        ciphertext = unhexlify(ciphertext)
        cipher = AES.new(key, AES.MODE_CFB, iv, segment_size=128)
        self.assertEqual(cipher.encrypt(plaintext), ciphertext)
        cipher = AES.new(key, AES.MODE_CFB, iv, segment_size=128)
        self.assertEqual(cipher.decrypt(ciphertext), plaintext)

    def test_aes_256(self):
        plaintext =     '6bc1bee22e409f96e93d7e117393172a' +\
                        'ae2d8a571e03ac9c9eb76fac45af8e51' +\
                        '30c81c46a35ce411e5fbc1191a0a52ef' +\
                        'f69f2445df4f9b17ad2b417be66c3710'
        ciphertext =    'dc7e84bfda79164b7ecd8486985d3860' +\
                        '39ffed143b28b1c832113c6331e5407b' +\
                        'df10132415e54b92a13ed0a8267ae2f9' +\
                        '75a385741ab9cef82031623d55b1e471'
        key =           '603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4'
        iv =            '000102030405060708090a0b0c0d0e0f'
        key = unhexlify(key)
        iv = unhexlify(iv)
        plaintext = unhexlify(plaintext)
        ciphertext = unhexlify(ciphertext)
        cipher = AES.new(key, AES.MODE_CFB, iv, segment_size=128)
        self.assertEqual(cipher.encrypt(plaintext), ciphertext)
        cipher = AES.new(key, AES.MODE_CFB, iv, segment_size=128)
        self.assertEqual(cipher.decrypt(ciphertext), plaintext)

class AES_OFB_TestVectors(unittest.TestCase):
    def test_aes_128(self):
        plaintext =     '6bc1bee22e409f96e93d7e117393172a' +\
                        'ae2d8a571e03ac9c9eb76fac45af8e51' +\
                        '30c81c46a35ce411e5fbc1191a0a52ef' +\
                        'f69f2445df4f9b17ad2b417be66c3710'
        ciphertext =    '3b3fd92eb72dad20333449f8e83cfb4a' +\
                        '7789508d16918f03f53c52dac54ed825' +\
                        '9740051e9c5fecf64344f7a82260edcc' +\
                        '304c6528f659c77866a510d9c1d6ae5e'
        key =           '2b7e151628aed2a6abf7158809cf4f3c'
        iv =            '000102030405060708090a0b0c0d0e0f'
        key = unhexlify(key)
        iv = unhexlify(iv)
        plaintext = unhexlify(plaintext)
        ciphertext = unhexlify(ciphertext)
        cipher = AES.new(key, AES.MODE_OFB, iv)
        self.assertEqual(cipher.encrypt(plaintext), ciphertext)
        cipher = AES.new(key, AES.MODE_OFB, iv)
        self.assertEqual(cipher.decrypt(ciphertext), plaintext)
        cipher = AES.new(key, AES.MODE_OFB, iv)
        self.assertEqual(cipher.encrypt(plaintext[:-8]), ciphertext[:-8])
        cipher = AES.new(key, AES.MODE_OFB, iv)
        self.assertEqual(cipher.decrypt(ciphertext[:-8]), plaintext[:-8])

    def test_aes_192(self):
        plaintext =     '6bc1bee22e409f96e93d7e117393172a' +\
                        'ae2d8a571e03ac9c9eb76fac45af8e51' +\
                        '30c81c46a35ce411e5fbc1191a0a52ef' +\
                        'f69f2445df4f9b17ad2b417be66c3710'
        ciphertext =    'cdc80d6fddf18cab34c25909c99a4174' +\
                        'fcc28b8d4c63837c09e81700c1100401' +\
                        '8d9a9aeac0f6596f559c6d4daf59a5f2' +\
                        '6d9f200857ca6c3e9cac524bd9acc92a'
        key =           '8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b'
        iv =            '000102030405060708090a0b0c0d0e0f'
        key = unhexlify(key)
        iv = unhexlify(iv)
        plaintext = unhexlify(plaintext)
        ciphertext = unhexlify(ciphertext)
        cipher = AES.new(key, AES.MODE_OFB, iv)
        self.assertEqual(cipher.encrypt(plaintext), ciphertext)
        cipher = AES.new(key, AES.MODE_OFB, iv)
        self.assertEqual(cipher.decrypt(ciphertext), plaintext)
        cipher = AES.new(key, AES.MODE_OFB, iv)
        self.assertEqual(cipher.encrypt(plaintext[:-8]), ciphertext[:-8])
        cipher = AES.new(key, AES.MODE_OFB, iv)
        self.assertEqual(cipher.decrypt(ciphertext[:-8]), plaintext[:-8])

    def test_aes_256(self):
        plaintext =     '6bc1bee22e409f96e93d7e117393172a' +\
                        'ae2d8a571e03ac9c9eb76fac45af8e51' +\
                        '30c81c46a35ce411e5fbc1191a0a52ef' +\
                        'f69f2445df4f9b17ad2b417be66c3710'
        ciphertext =    'dc7e84bfda79164b7ecd8486985d3860' +\
                        '4febdc6740d20b3ac88f6ad82a4fb08d' +\
                        '71ab47a086e86eedf39d1c5bba97c408' +\
                        '0126141d67f37be8538f5a8be740e484'
        key =           '603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4'
        iv =            '000102030405060708090a0b0c0d0e0f'
        key = unhexlify(key)
        iv = unhexlify(iv)
        plaintext = unhexlify(plaintext)
        ciphertext = unhexlify(ciphertext)
        cipher = AES.new(key, AES.MODE_OFB, iv)
        self.assertEqual(cipher.encrypt(plaintext), ciphertext)
        cipher = AES.new(key, AES.MODE_OFB, iv)
        self.assertEqual(cipher.decrypt(ciphertext), plaintext)
        cipher = AES.new(key, AES.MODE_OFB, iv)
        self.assertEqual(cipher.encrypt(plaintext[:-8]), ciphertext[:-8])
        cipher = AES.new(key, AES.MODE_OFB, iv)
        self.assertEqual(cipher.decrypt(ciphertext[:-8]), plaintext[:-8])
        
def main():     
    test1 = AES_CBC_TestVectors()
    test1.test_aes_128() 
    test1.test_aes_192() 
    test1.test_aes_256() 
    print("AES_CBC_TestVectors OK!")    

    test1 = AES_ECB_TestVectors()
    test1.test_aes_128() 
    test1.test_aes_192() 
    test1.test_aes_256() 
    print("AES_ECB_TestVectors OK!")    

    test1 = AES_CFB_TestVectors()
    test1.test_aes_128() 
    test1.test_aes_192() 
    test1.test_aes_256() 
    print("AES_CFB_TestVectors OK!")    

    test1 = AES_OFB_TestVectors()
    test1.test_aes_128() 
    test1.test_aes_192() 
    test1.test_aes_256() 
    print("AES_OFB_TestVectors OK!")  
    

                  
    key = b'abf7158809cf4f3c'
    iv = b'0001020304050607'
    data = b'f69f2445df4f9b17ad2b417be66c3710'
    result = AES_128_CBC_ENC(data, iv, key)
    assert result.hex() == '83765c095e3cd1a00ea476805e8e067509d91966275f3249e3c70a6ef08e73d8'    
    
    result = AES_128_CBC_DEC(data, iv, key)
    assert result.hex() == '290477456dc6497bde68317f32852f06d7b3b4acb95a49a87fd808e5879e90b4'    
    print("AES_128_CBC OK!")  
    
    key = b'809079e562f8ead2522c6b7b'
    result = AES_192_CBC_ENC(data, iv, key)
    assert result.hex() == '53fa6ea98bcc88ce3f488e17d5c3206c3a2a48a5e13839dd3008be24b3692fb4'    
    
    result = AES_192_CBC_DEC(data, iv, key)
    assert result.hex() == 'a86bfc9204a1b0d62b74e0788f4140bb193c058252244087d24eb851ecbe882c'    
    print("AES_192_CBC OK!")  
    
    key = b'1f352c073b6108d72d9810a30914dff4' 
    result = AES_256_CBC_ENC(data, iv, key)
    assert result.hex() == '8b4226c7e9a01a28f7e382c7040ab2f3a86fc2dd0f05a7d75a17c2f4c96a9a65'    
    
    result = AES_256_CBC_DEC(data, iv, key)
    assert result.hex() == 'ee3e7059721d967c22e1f5fab33eba138a38b4b50c1b34a833bff6647d043dcf'    
    print("AES_256_CBC OK!")  
    
    key = b'abf7158809cf4f3c'
    result = AES_128_ECB_ENC(data, key)
    assert result.hex() == '1ce8facf93c7d80009191e2270d72cf09eb92a65b54283bb50b51b803233c826'    
    
    result = AES_128_ECB_DEC(data, key)
    assert result.hex() == '193447745df47948ee5c014a02b31f31b1858dca8b6e7d9d1bbe3c83befca183'    
    print("AES_128_ECB OK!") 
    
    key = b'809079e562f8ead2522c6b7b'
    result = AES_192_ECB_ENC(data, key)
    assert result.hex() == 'fd4b376f7a351e95504cd993485a52babfed73e5584a72eb5ced4a81d669ba09'    
    
    result = AES_192_ECB_DEC(data, key)
    assert result.hex() == '985bcca3349380e51b40d04dbf77708c7f0a3ce4601074b2b6288c37d5dcb91b'    
    print("AES_192_ECB OK!") 
    
    key = b'1f352c073b6108d72d9810a30914dff4' 
    result = AES_256_ECB_ENC(data, key)
    assert result.hex() == '8f01d7c75a2a9afc17b09f51bef7816e395b6a26d314ddccf1f44afe58f5f71f'    
    
    result = AES_256_ECB_DEC(data, key)
    assert result.hex() == 'de0e4068422fa64f12d5c5cf83088a24ec0e8dd33e2f009d57d9c20244660cf8'    
    print("AES_256_ECB OK!") 
    
    key = b'abf7158809cf4f3c'
    result = AES_128_CFB_ENC(data, iv, key)
    assert result.hex() == '712099759d52b21b8e0032d2424e4c8f735aa3f7d56c68a43b6e86de411ea9fa'    
    
    result = AES_128_CFB_DEC(data, iv, key)
    assert result.hex() == '712099759d52b21b8e0032d2424e4c8f7d8cc8ada7f6ef626c2f284143e01dc0'    
    print("AES_128_CFB OK!") 
    
    key = b'809079e562f8ead2522c6b7b'
    result = AES_192_CFB_ENC(data, iv, key)
    assert result.hex() == '6097c1961b2d06571ade418faa24f282107d92ed6ba34d7f9961357ee2a20a55'    
    
    result = AES_192_CFB_DEC(data, iv, key)
    assert result.hex() == '6097c1961b2d06571ade418faa24f2829c2f050d4e0429f7357aeff07b6d638a'    
    print("AES_192_CFB OK!") 
    
    key = b'1f352c073b6108d72d9810a30914dff4' 
    result = AES_256_CFB_ENC(data, iv, key)
    assert result.hex() == '441e9ba77275dc6ac27481fe98e6629ae040e4289eeb88f6ddb7966dcdfacdbd'    
    
    result = AES_256_CFB_DEC(data, iv, key)
    assert result.hex() == '441e9ba77275dc6ac27481fe98e6629aee65e5a56e1bad9e7286a9328dc0b05e'    
    print("AES_256_CFB OK!") 
    
    key = b'abf7158809cf4f3c'
    result = AES_128_OFB_ENC(data, iv, key)
    assert result.hex() == '712099759d52b21b8e0032d2424e4c8fe118d10a2d5e5e2beb7b590bdbd0ffd1'    
    
    result = AES_128_OFB_DEC(data, iv, key)
    assert result.hex() == '712099759d52b21b8e0032d2424e4c8fe118d10a2d5e5e2beb7b590bdbd0ffd1'    
    print("AES_128_OFB OK!") 
    
    key = b'809079e562f8ead2522c6b7b'
    result = AES_192_OFB_ENC(data, iv, key)
    assert result.hex() == '6097c1961b2d06571ade418faa24f28226a727a46d4c028cddfd7f4fdbae7355'    
    
    result = AES_192_OFB_DEC(data, iv, key)
    assert result.hex() == '6097c1961b2d06571ade418faa24f28226a727a46d4c028cddfd7f4fdbae7355'    
    print("AES_192_OFB OK!") 
    
    key = b'1f352c073b6108d72d9810a30914dff4' 
    result = AES_256_OFB_ENC(data, iv, key)
    assert result.hex() == '441e9ba77275dc6ac27481fe98e6629a0a8109b53c45d315278894d4a79852ff'    
    
    result = AES_256_OFB_DEC(data, iv, key)
    assert result.hex() == '441e9ba77275dc6ac27481fe98e6629a0a8109b53c45d315278894d4a79852ff'    
    print("AES_256_OFB OK!") 
    
if __name__ == '__main__':
    main()

