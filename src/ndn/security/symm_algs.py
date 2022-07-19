# -----------------------------------------------------------------------------
# Copyright (C) 2019-2020 The python-ndn authors
#
# Created by liupenghui, package the AES symmetric algorithms excluding SM4.  
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
from binascii import unhexlify
from Cryptodome.SelfTest.loader import load_test_vectors
from Cryptodome.SelfTest.st_common import list_test_cases
from Cryptodome.Util.py3compat import tobytes, is_string
from Cryptodome.Cipher import AES, DES3, DES
from Cryptodome.Hash import SHAKE128, SHA256

def AES_128_CBC_ENC(plaintext: bytearray, iv: bytearray, key: bytearray):
    assert len(key) == 16

    cipher = AES.new(key, AES.MODE_CBC, iv)
    return cipher.encrypt(plaintext)

def AES_128_CBC_DEC(ciphertext: bytearray, iv: bytearray, key: bytearray):
    assert len(key) == 16

    cipher = AES.new(key, AES.MODE_CBC, iv)
    return cipher.decrypt(ciphertext)

def AES_192_CBC_ENC(plaintext: bytearray, iv: bytearray, key: bytearray):
    assert len(key) == 24

    cipher = AES.new(key, AES.MODE_CBC, iv)
    return cipher.encrypt(plaintext)

def AES_192_CBC_DEC(ciphertext: bytearray, iv: bytearray, key: bytearray):
    assert len(key) == 24

    cipher = AES.new(key, AES.MODE_CBC, iv)
    return cipher.decrypt(ciphertext)

def AES_256_CBC_ENC(plaintext: bytearray, iv: bytearray, key: bytearray):
    assert len(key) == 32

    cipher = AES.new(key, AES.MODE_CBC, iv)
    return cipher.encrypt(plaintext)

def AES_256_CBC_DEC(ciphertext: bytearray, iv: bytearray, key: bytearray):
    assert len(key) == 32
    
    cipher = AES.new(key, AES.MODE_CBC, iv)
    return cipher.decrypt(ciphertext)

def AES_128_ECB_ENC(plaintext: bytearray, key: bytearray):
    assert len(key) == 16        
    # Run tests without hardware AES-NI instructions.
    cipher = AES.new(key, AES.MODE_ECB, use_aesni = False)
    return cipher.encrypt(plaintext)

def AES_128_ECB_DEC(ciphertext: bytearray, key: bytearray):
    assert len(key) == 16        
    # Run tests without hardware AES-NI instructions.
    cipher = AES.new(key, AES.MODE_ECB, use_aesni = False)
    return cipher.decrypt(ciphertext)
    
def AES_192_ECB_ENC(plaintext: bytearray, key: bytearray):
    assert len(key) == 24        
    # Run tests without hardware AES-NI instructions.
    cipher = AES.new(key, AES.MODE_ECB, use_aesni = False)
    return cipher.encrypt(plaintext)

def AES_192_ECB_DEC(ciphertext: bytearray, key: bytearray):
    assert len(key) == 24    
    # Run tests without hardware AES-NI instructions.
    cipher = AES.new(key, AES.MODE_ECB, use_aesni = False)
    return cipher.decrypt(ciphertext)        

def AES_256_ECB_ENC(plaintext: bytearray, key: bytearray):
    assert len(key) == 32
    # Run tests without hardware AES-NI instructions.
    cipher = AES.new(key, AES.MODE_ECB, use_aesni = False)
    return cipher.encrypt(plaintext)

def AES_256_ECB_DEC(ciphertext: bytearray, key: bytearray):
    assert len(key) == 32
    # Run tests without hardware AES-NI instructions.
    cipher = AES.new(key, AES.MODE_ECB, use_aesni = False)
    return cipher.decrypt(ciphertext)  

def AES_128_CFB_ENC(plaintext: bytearray, iv: bytearray, key: bytearray):
    assert len(key) == 16

    cipher = AES.new(key, AES.MODE_CFB, iv, segment_size=128)
    return cipher.encrypt(plaintext)  

def AES_128_CFB_DEC(ciphertext: bytearray, iv: bytearray, key: bytearray):
    assert len(key) == 16
    
    cipher = AES.new(key, AES.MODE_CFB, iv, segment_size=128)
    return cipher.decrypt(ciphertext)  
   
def AES_192_CFB_ENC(plaintext: bytearray, iv: bytearray, key: bytearray):
    assert len(key) == 24

    cipher = AES.new(key, AES.MODE_CFB, iv, segment_size=128)
    return cipher.encrypt(plaintext)  

def AES_192_CFB_DEC(ciphertext: bytearray, iv: bytearray, key: bytearray):
    assert len(key) == 24
    
    cipher = AES.new(key, AES.MODE_CFB, iv, segment_size=128)
    return cipher.decrypt(ciphertext)
    
def AES_256_CFB_ENC(plaintext: bytearray, iv: bytearray, key: bytearray):
    assert len(key) == 32

    cipher = AES.new(key, AES.MODE_CFB, iv, segment_size=128)
    return cipher.encrypt(plaintext)  

def AES_256_CFB_DEC(ciphertext: bytearray, iv: bytearray, key: bytearray):
    assert len(key) == 32
    
    cipher = AES.new(key, AES.MODE_CFB, iv, segment_size=128)
    return cipher.decrypt(ciphertext)        


def AES_128_OFB_ENC(plaintext: bytearray, iv: bytearray, key: bytearray):
    assert len(key) == 16

    cipher = AES.new(key, AES.MODE_OFB, iv)
    return cipher.encrypt(plaintext)  

def AES_128_OFB_DEC(ciphertext: bytearray, iv: bytearray, key: bytearray):
    assert len(key) == 16
    
    cipher = AES.new(key, AES.MODE_OFB, iv)
    return cipher.decrypt(ciphertext) 

def AES_192_OFB_ENC(plaintext: bytearray, iv: bytearray, key: bytearray):
    assert len(key) == 24

    cipher = AES.new(key, AES.MODE_OFB, iv)
    return cipher.encrypt(plaintext)  

def AES_192_OFB_DEC(ciphertext: bytearray, iv: bytearray, key: bytearray):
    assert len(key) == 24
    
    cipher = AES.new(key, AES.MODE_OFB, iv)
    return cipher.decrypt(ciphertext) 
    
def AES_256_OFB_ENC(plaintext: bytearray, iv: bytearray, key: bytearray):
    assert len(key) == 32

    cipher = AES.new(key, AES.MODE_OFB, iv)
    return cipher.encrypt(plaintext)  

def AES_256_OFB_DEC(ciphertext: bytearray, iv: bytearray, key: bytearray):
    assert len(key) == 32
    
    cipher = AES.new(key, AES.MODE_OFB, iv)
    return cipher.decrypt(ciphertext)

