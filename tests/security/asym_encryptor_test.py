# -----------------------------------------------------------------------------
# Copyright (C) 2019-2020 The python-ndn authors
#
# Created by liupenghui, Show how to encrypt/decrypt a byte message using asymmetric algorithms.  
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
from ndn.encoding import make_data, make_interest, InterestParam, parse_interest, MetaInfo, parse_data, Name
from ndn.security import sm2, sm3, func
from ndn.platform import Platform
from ndn.client_conf import default_keychain
from ndn.security.keychain import KeychainSqlite3
from Cryptodome.PublicKey import (_expand_subject_public_key_info,
                              _create_subject_public_key_info,
                              _extract_subject_public_key_info)                             
from Cryptodome.Cipher import PKCS1_OAEP, PKCS1_v1_5
from Cryptodome.PublicKey import RSA

# Below section is added by liupenghui to show how to use an existing asymmetric key in PIB to sign Data or Interest          
def GetPublicBytes(public_key: str) -> bytes:
    para_len = len('FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFF7203DF6B21C6052B53BBF40939D54123')
    px = int(public_key[0:para_len], 16)
    py = int(public_key[para_len:2 * para_len], 16)   
    #SEC1_public_key = (b'\x04' + px.to_bytes(para_len >> 1,'big') + py.to_bytes(para_len >> 1,'big'))
    SEC1_public_key = (b'\x04' + long_to_bytes(px, para_len >> 1) + long_to_bytes(py, para_len >> 1))
    unrestricted_oid = "1.2.840.10045.2.1"
    #pub_key and key_der format = 'DER', pri_key use_pkcs8=true
    pub_key = bytes(_create_subject_public_key_info(unrestricted_oid, SEC1_public_key, DerObjectId("1.2.840.10045.3.1.7"))) 
    return pub_key    

# Get the default keychain 'KeychainSqlite3'
def GetKeyChain()-> KeychainSqlite3:
    tpm = None
    tpm_path = None
    base_dir = None
    platform = Platform()
    if not tpm:
        tpm = platform.default_tpm_scheme()
    if tpm == 'tpm-osxkeychain' and sys.platform != 'darwin':
        print(f'ERROR: {tpm} only works on MacOS.')
        exit(-2)
    if tpm == 'tpm-cng' and sys.platform != 'win32':
        print(f'ERROR: {tpm} only works on Windows 10/11 with a TPM chip.')
        exit(-2)
    if not base_dir:
        for d in platform.default_pib_paths():
            if os.path.exists(d):
                base_dir = d
                break
        if not base_dir:
            print('ERROR: Cannot find a PIB.')
            exit(-2)

    pib_path = os.path.join(base_dir, 'pib.db')
    if not os.path.exists(pib_path):
        print(f'ERROR: Specified or default PIB database file {pib_path} does not exist.')
        exit(-2)

    if not tpm_path:
        if tpm == 'tpm-file':
            tpm_path = os.path.join(base_dir, 'ndnsec-key-file')
        else:
            tpm_path = ''

    return default_keychain(f'pib-sqlite3:{base_dir}', f'{tpm}:{tpm_path}') 

# Test Encrypt a byte message With SM2 Key in PIB.
class TestEncryptDataWithSM2KeyName:
    def test_data(self):
        # Encrypt Data with a existed key named('/mytest1/KEY/%82%D2%3E~%09%11N%DB'), key_type='sm2'  
        # please confirm your PIB has this named asymmetric sm2 key (/mytest1/KEY/%82%D2%3E~%09%11N%DB) using command pyndnsec list -vvv or ndnsec list -vvv
        key_name= "/mytest1/KEY/%82%D2%3E~%09%11N%DB"
        key_type= 'sm2'
        kc = GetKeyChain()
        key_type = kc.get_key_type(key_name);
        assert key_type == 'sm2'
        key_name = Name.normalize(key_name)
        #print(to_str(key_name))
        pri_key, pub_key, key_der = kc.tpm.get_pulic_private_keys(key_name, key_type)
        sm2_crypt = sm2.CryptSM2(
            public_key=pub_key, private_key=pri_key)
        #data size shoule be less than the ORDER as per the requirement of SM2    
        data = b"111"
        print("\n-----------------test SM2 encrypt and decrypt--------------")
        enc_data = sm2_crypt.encrypt(data)
        dec_data = sm2_crypt.decrypt(enc_data)
        print(b"data:%s" % data)  
        print("enc_data:%s" % enc_data.hex()) # 转化为16进制字符串输出
        print(b"dec_data:%s" % dec_data)
        assert data == dec_data

 
# Test Sign a byte message With RSA Key in PIB by PKCS1_OAEP.
class TestEncryptDataWithRSAKeyName:
    def test_data(self):
        # sign Data with a existed key named('/mytest3/KEY/ezu%3AJ%26%2A%15'), key_type='rsa'  
        # please confirm your PIB has this named asymmetric RSA key (/mytest3/KEY/ezu%3AJ%26%2A%15) using command pyndnsec list -vvv or ndnsec list -vvv
        key_name= "/mytest3/KEY/ezu%3AJ%26%2A%15"
        key_type= 'rsa'
        kc = GetKeyChain()
        key_type = kc.get_key_type(key_name);
        assert key_type == 'rsa'           
        key_name = Name.normalize(key_name)
        #print(to_str(key_name))
        pri_key, pub_key, key_der = kc.tpm.get_pulic_private_keys(key_name, key_type)
        key = RSA.import_key(key_der)
        #data size shoule be less than the 190 bytes as per the requirement of SM2   
        data = b"111"
        print("\n-----------------test RSA PKCS1_OAEP encrypt and decrypt--------------")
        PKCS1OAEP_cipher = PKCS1_OAEP.new(key)
        enc_data = PKCS1OAEP_cipher.encrypt(data)       
        dec_data = PKCS1OAEP_cipher.decrypt(enc_data)
        print(b"data:%s" % data)  
        print("enc_data:%s" % enc_data.hex()) # 转化为16进制字符串输出
        print(b"dec_data:%s" % dec_data)
        assert data == dec_data  

# Test Sign a byte message With RSA Key in PIB by PKCS1_v1_5.
class TestEncryptDataWithRSAKeyName_PKCS1_v1_5:
    def test_data(self):
        # sign Data with a existed key named('/mytest3/KEY/ezu%3AJ%26%2A%15'), key_type='rsa'  
        # please confirm your PIB has this named asymmetric RSA key (/mytest3/KEY/ezu%3AJ%26%2A%15) using command pyndnsec list -vvv or ndnsec list -vvv
        key_name= "/mytest3/KEY/ezu%3AJ%26%2A%15"
        key_type= 'rsa'
        kc = GetKeyChain()
        key_type = kc.get_key_type(key_name);
        assert key_type == 'rsa'           
        key_name = Name.normalize(key_name)
        #print(to_str(key_name))
        pri_key, pub_key, key_der = kc.tpm.get_pulic_private_keys(key_name, key_type)
        key = RSA.import_key(key_der)
        #data size shoule be less than the 190 bytes as per the requirement of SM2   
        data = b"111"
        sentinel = b"123"
        print("\n-----------------test RSA PKCS1_v1_5 encrypt and decrypt--------------")
        PKCS15_cipher = PKCS1_v1_5.new(key)
        enc_data = PKCS15_cipher.encrypt(data)   
        #sentinel must be random data of the same length with original data.        
        dec_data = PKCS15_cipher.decrypt(enc_data, sentinel)
        print(b"data:%s" % data)  
        print("enc_data:%s" % enc_data.hex()) # 转化为16进制字符串输出
        print(b"dec_data:%s" % dec_data)
        assert data == dec_data  
 
def main():     
    test1 = TestEncryptDataWithSM2KeyName()
    test1.test_data() 
    print("TestEncryptDataWithSM2KeyName OK!")    

    test1 = TestEncryptDataWithRSAKeyName()
    test1.test_data() 
    print("TestEncryptDataWithRSAKeyName OK!")    

    test1 = TestEncryptDataWithRSAKeyName_PKCS1_v1_5()
    test1.test_data() 
    print("TestEncryptDataWithRSAKeyName_PKCS1_v1_5 OK!")       
if __name__ == '__main__':
    main()
