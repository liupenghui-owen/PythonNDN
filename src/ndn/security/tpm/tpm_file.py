# -----------------------------------------------------------------------------
# Copyright (C) 2019-2020 The python-ndn authors
#
# This file is part of python-ndn.
# Modified by liupenghui, added sm2 key generation and sm2 signer support
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
import os
from base64 import b64decode, b64encode
from hashlib import sha256
from typing import Tuple
from Cryptodome.PublicKey import RSA, ECC
from Cryptodome.Math.Numbers import Integer
from Cryptodome.Random import get_random_bytes
from ...encoding import Signer, NonStrictName, Name, BinaryStr, FormalName
from ..signer.sha256_rsa_signer import Sha256WithRsaSigner
from ..signer.sha256_ecdsa_signer import Sha256WithEcdsaSigner
from ..signer.sm3_sm2_signer import Sm3WithSm2Signer
from .tpm import Tpm
from ...security import sm2, func
from Cryptodome.Util.py3compat import bord, tobytes, tostr, bchr, is_string
import binascii
from Cryptodome.PublicKey import _create_subject_public_key_info
from Cryptodome.Util.asn1 import (DerObjectId, DerOctetString, DerSequence,
                              DerBitString)
from Cryptodome.Util.number import long_to_bytes, bytes_to_long
                              
class TpmFile(Tpm):
    path: str

    def __init__(self, path):
        self.path = path

    @staticmethod
    def _to_file_name(key_name: bytes):
        return sha256(key_name).digest().hex() + '.privkey'

    @staticmethod
    def _base64_newline(src: bytes):
        return b'\n'.join(src[i*64:i*64+64] for i in range((len(src) + 63) // 64))

    # added sm2 signer by liupenghui
    # due to SM2 key format is the same as ECDSA, so we add a key type parameter key_type.
    def get_pulic_private_keys(self, key_name: NonStrictName, key_type: str = 'ec'):
        key_name = Name.to_bytes(key_name)
        file_name = os.path.join(self.path, self._to_file_name(key_name))
        if not os.path.exists(file_name):
            raise KeyError(key_name)
        with open(file_name, 'rb') as f:
            key_b64 = f.read()
        key_der = tobytes(b64decode(key_b64))
        
        if key_type == 'rsa':
            try:
                key = RSA.import_key(key_der)                
                pri_key = '%0512x%0512x' % (key.n, key.d)
                pub_key = '%0512x%0512x' % (key.n, key.e)                
                return pri_key, pub_key, key_der
                
            except ValueError:
                pass        
            
        if key_type == 'ec' or key_type == 'sm2':
            encoded = key_der
            try:
                #try pkcs1 der format decoding
                private_key = DerSequence().decode(encoded, nr_elements=(3, 4))
                if private_key[0] != 1:
                    raise ValueError("Incorrect SM2 private key version")

                try:
                    parameters = DerObjectId(explicit=0).decode(private_key[2]).value
                    curve_oid = parameters
                except ValueError:
                    pass

                if curve_oid is None:
                    raise ValueError("No sm2 ECC curve found")

                scalar_bytes = DerOctetString().decode(private_key[1]).payload
                modulus_bytes = 32
                if len(scalar_bytes) != modulus_bytes:
                    raise ValueError("Private sm2 key is too small")
                #d = Integer.from_bytes(scalar_bytes)
                d = Integer(bytes_to_long(scalar_bytes))
                para_len = len('FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFF7203DF6B21C6052B53BBF40939D54123')
                form = '%%0%dx' % para_len
                pri_key = form % d
                if len(private_key) == 4:
                    public_key_enc = DerBitString(explicit=1).decode(private_key[3]).value
                    if len(public_key_enc) != (1 + 2 * modulus_bytes):
                        raise ValueError("Incorrect EC point length")
                    #x = Integer.from_bytes(public_key_enc[1:modulus_bytes+1])
                    #y = Integer.from_bytes(public_key_enc[modulus_bytes+1:])
                    x = Integer(bytes_to_long(public_key_enc[1:modulus_bytes+1]))
                    y = Integer(bytes_to_long(public_key_enc[modulus_bytes+1:])) 
                    form = '%%0%dx' % para_len
                    form = form * 2
                    pub_key = form % (x, y)     
                    return pri_key, pub_key, key_der                    
                else:
                    raise ValueError("No point x, y found")
                
            except UnsupportedEccFeature as err:
                pass
            except (ValueError, TypeError, IndexError):
                pass
                        
            try:
                #try pkcs8 der format decoding       
                algo_oid, enc_private_key, params = PKCS8.unwrap(encoded)
                curve_oid = DerObjectId().decode(params).value
                private_key = DerSequence().decode(enc_private_key, nr_elements=(3, 4))
                if private_key[0] != 1:
                    raise ValueError("Incorrect SM2 private key version")

                #try:
                #    parameters = DerObjectId(explicit=0).decode(private_key[2]).value
                #    curve_oid = parameters
                #except ValueError:
                #    pass

                #if curve_oid is None:
                #    raise ValueError("No sm2 ECC curve found")

                scalar_bytes = DerOctetString().decode(private_key[1]).payload
                modulus_bytes = 32
                if len(scalar_bytes) != modulus_bytes:
                    raise ValueError("Private sm2 key is too small")
                #d = Integer.from_bytes(scalar_bytes)
                d = Integer(bytes_to_long(scalar_bytes))
                para_len = len('FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFF7203DF6B21C6052B53BBF40939D54123')
                form = '%%0%dx' % para_len
                pri_key = form % d
                if len(private_key) == 3:
                    public_key_enc = DerBitString(explicit=1).decode(private_key[2]).value
                    if len(public_key_enc) != (1 + 2 * modulus_bytes):
                        raise ValueError("Incorrect EC point length")
                    #x = Integer.from_bytes(public_key_enc[1:modulus_bytes+1])
                    #y = Integer.from_bytes(public_key_enc[modulus_bytes+1:])
                    x = Integer(bytes_to_long(public_key_enc[1:modulus_bytes+1]))
                    y = Integer(bytes_to_long(public_key_enc[modulus_bytes+1:]))                      
                    form = '%%0%dx' % para_len
                    form = form * 2
                    pub_key = form % (x, y)  
                    return pri_key, pub_key, key_der                        
                else:
                    raise ValueError("No pkcs8 point x, y found")
                    
            except UnsupportedEccFeature as err:
                raise err
            except (ValueError, TypeError, IndexError):
                raise ValueError("Not an SM2 ECC DER key")        
               
        raise ValueError('Key format is not supported')
        
    # added sm2 signer by liupenghui
    # due to SM2 key format is the same as ECDSA, so we add a key type parameter key_type.
    def get_signer(self, key_name: NonStrictName, key_type: str = 'ec') -> Signer:
        key_name = Name.to_bytes(key_name)
        file_name = os.path.join(self.path, self._to_file_name(key_name))
        if not os.path.exists(file_name):
            raise KeyError(key_name)
        with open(file_name, 'rb') as f:
            key_b64 = f.read()
        key_der = b64decode(key_b64)
        
        if key_type == 'sm2':
            try:
                return Sm3WithSm2Signer(key_name, key_der)
            except ValueError:
                pass        
            
        for signer in [Sha256WithRsaSigner, Sha256WithEcdsaSigner]:
            try:
                return signer(key_name, key_der)
            except ValueError:
                pass
        raise ValueError('Key format is not supported')

    def key_exist(self, key_name: FormalName) -> bool:
        key_name = Name.encode(key_name)
        file_name = os.path.join(self.path, self._to_file_name(key_name))
        return os.path.exists(file_name)

    def save_key(self, key_name: FormalName, key_der: BinaryStr):
        key_name = Name.encode(key_name)
        key_b64 = self._base64_newline(b64encode(key_der))
        file_name = os.path.join(self.path, self._to_file_name(key_name))
        with open(file_name, 'wb') as f:
            f.write(key_b64)

    def delete_key(self, key_name: FormalName):
        key_name = Name.encode(key_name)
        file_name = os.path.join(self.path, self._to_file_name(key_name))
        try:
            os.remove(file_name)
        except FileNotFoundError:
            pass
            
    # added sm2 key generation by liupenghui
    def generate_key(self, id_name: FormalName, key_type: str = 'rsa', **kwargs) -> Tuple[FormalName, BinaryStr]:
        if key_type == 'rsa':
            siz = kwargs.pop('key_size', 2048)
            pri_key = RSA.generate(siz)
            pub_key = pri_key.publickey().export_key(format='DER')
            key_der = pri_key.export_key(format='DER', pkcs=1)
        elif key_type == 'ec':
            siz = kwargs.pop('key_size', 256)
            pri_key = ECC.generate(curve=f'P-{siz}')
            pub_key = bytes(pri_key.public_key().export_key(format='DER'))
            key_der = pri_key.export_key(format='DER', use_pkcs8=False)
        elif key_type == 'sm2':
            # random generate private key following the sm2 curve.
            #'n': 'FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFF7203DF6B21C6052B53BBF40939D54123',
            #'p': 'FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFF',
            #'g': '32c4ae2c1f1981195f9904466a39c9948fe30bbff2660be1715a4589334c74c7'
            #'bc3736a2f4f6779c59bdcee36b692153d0a9877cc62a474002df32e52139f0a0',
            #'a': 'FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFC',
            #'b': '28E9FA9E9D9F5E344D5A9E4BCF6509A7F39789F515AB8F92DDBCBD414D940E93',
            # SM2 private key use pcks1 DER format, like ECSDSA. 
            
            d = Integer.random_range(min_inclusive=1,
                                     max_exclusive=int('FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFF7203DF6B21C6052B53BBF40939D54123', base=16),
                                     randfunc=get_random_bytes)
            para_len = len('FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFF7203DF6B21C6052B53BBF40939D54123')
            form = '%%0%dx' % para_len
            private_key = form % d
            # below public_key is fake public key, will be updated to a true one immediately. just for initiation.
            public_key = 'B9C9A6E04E9C91F7BA880429273747D7EF5DDEB0BB2FF6317EB00BEF331A83081A6994B8993F3F5D6EADDDB81872266C87C018FB4162F5AF347B483E24620207'
            sm2_sign = sm2.CryptSM2(public_key=public_key, private_key=private_key)
            s = int(private_key, 16)
            # public_key= sG is a true public key.
            public_key = sm2_sign._kg(s, '32c4ae2c1f1981195f9904466a39c9948fe30bbff2660be1715a4589334c74c7bc3736a2f4f6779c59bdcee36b692153d0a9877cc62a474002df32e52139f0a0')
            px = int(public_key[0:para_len], 16)
            py = int(public_key[para_len:2 * para_len], 16)
            #SEC1_public_key = (b'\x04' + px.to_bytes(para_len >> 1, 'big') + py.to_bytes(para_len >> 1,'big'))
            SEC1_public_key = (b'\x04' + long_to_bytes(px, para_len >> 1) + long_to_bytes(py, para_len >> 1))
            unrestricted_oid = "1.2.840.10045.2.1"
            #pub_key and key_der format = 'DER', pri_key use_pkcs8=False
            pub_key = bytes(_create_subject_public_key_info(unrestricted_oid, SEC1_public_key, DerObjectId("1.2.156.10197.1.301")))
            #seq = [1, DerOctetString(s.to_bytes(para_len >> 1,'big')), DerObjectId("1.2.840.10045.3.1.7", explicit=0), DerBitString(SEC1_public_key, explicit=1)]  
            seq = [1, DerOctetString(long_to_bytes(s, para_len >> 1)), DerObjectId("1.2.156.10197.1.301", explicit=0), DerBitString(SEC1_public_key, explicit=1)]  
            key_der = DerSequence(seq).encode()           
        else:
            raise ValueError(f'Unsupported key type {key_type}')
        key_name = self.construct_key_name(id_name, pub_key, **kwargs)
        self.save_key(key_name, key_der)
        return key_name, pub_key

