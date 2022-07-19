# -----------------------------------------------------------------------------
# Copyright (C) 2019-2020 The python-ndn authors
#
# This file is part of python-ndn.
# created by liupenghui, support sm2 signer with sm3
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
from typing import List, Union
from Cryptodome.Hash import SHA256
from Cryptodome.PublicKey import ECC
from Cryptodome.Signature import DSS
from ...encoding import Signer, SignatureType, KeyLocator, NonStrictName, VarBinaryStr
from ...security import sm2, sm3, func
from Cryptodome.Math.Numbers import Integer
from Cryptodome.Util.py3compat import bord, tobytes, tostr, bchr, is_string
from Cryptodome.Util.number import long_to_bytes
from Cryptodome.Util.asn1 import (DerObjectId, DerOctetString, DerSequence,
                              DerBitString)
from Cryptodome.IO import PKCS8
from Cryptodome.Util.number import long_to_bytes, bytes_to_long

class UnsupportedEccFeature(ValueError):
    pass
    
class Sm3WithSm2Signer(Signer):
    # Sm3 works with Sm2, currently
    key_name: NonStrictName
    key_der: bytes
    curve_bit: int
    key_size: int
    pri_key: str
    pub_key: str
    
    def __init__(self, key_name: NonStrictName, key_der: Union[bytes, str]):
        self.key_name = key_name
        self.key_der = key_der
        self.pri_key = 'NULL';
        self.pub_key = 'NULL';
        
        self.curve_bit = 256
        self.key_size = (self.curve_bit * 2 + 7) // 8
        self.key_size += self.key_size % 2

        encoded = tobytes(key_der)
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
            # See RFC5915 https://tools.ietf.org/html/rfc5915
            #
            # ECPrivateKey ::= SEQUENCE {
            #           version        INTEGER { ecPrivkeyVer1(1) } (ecPrivkeyVer1),
            #           privateKey     OCTET STRING,
            #           parameters [0] ECParameters {{ NamedCurve }} OPTIONAL,
            #           publicKey  [1] BIT STRING OPTIONAL
            #    }     
            
            # keep in line with sm2 curve order length       
            #'n': 'FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFF7203DF6B21C6052B53BBF40939D54123',
            #'p': 'FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFF',
            #'g': '32c4ae2c1f1981195f9904466a39c9948fe30bbff2660be1715a4589334c74c7'
            #'bc3736a2f4f6779c59bdcee36b692153d0a9877cc62a474002df32e52139f0a0',
            #'a': 'FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFC',
            #'b': '28E9FA9E9D9F5E344D5A9E4BCF6509A7F39789F515AB8F92DDBCBD414D940E93',   
            para_len = len('FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFF7203DF6B21C6052B53BBF40939D54123')
            form = '%%0%dx' % para_len
            self.pri_key = form % d
            #print('\nsm3_sm2_signer private_key:')
            #print(self.pri_key)    
            
            # Decode public key (if any)
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
                self.pub_key = form % (x, y)     
                #print('\nsm3_sm2_signer pub_key:')
                #print(self.pub_key)                   
            else:
                raise ValueError("No point x, y found")
            # got a result;    
            return
        except UnsupportedEccFeature as err:
            pass
        except (ValueError, TypeError, IndexError):
            pass
                    
        try:
            #try pkcs8 der format decoding       
            algo_oid, enc_private_key, params = PKCS8.unwrap(encoded)
            #curve_oid = DerObjectId().decode(params).value
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
            self.pri_key = form % d
            #print('\nsm3_sm2_signer private_key:')
            #print(self.pri_key)  
                        
            
            # Decode public key (if any)
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
                self.pub_key = form % (x, y)  
                #print('\nsm3_sm2_signer pub_key:')
                #print(self.pub_key)                 
            else:
                raise ValueError("No pkcs8 point x, y found") 
        except UnsupportedEccFeature as err:
            raise err
        except (ValueError, TypeError, IndexError):
            raise ValueError("Not an SM2 ECC DER key")        

    def write_signature_info(self, signature_info):
        signature_info.signature_type = SignatureType.SM3_WITH_SM2
        signature_info.key_locator = KeyLocator()
        signature_info.key_locator.name = self.key_name

    def get_signature_value_size(self):
        return self.key_size + 8

    def write_signature_value(self, wire: VarBinaryStr, contents: List[VarBinaryStr]) -> int:
        content = []
        for blk in contents:
            content.extend(func.bytes_to_list(blk))
            
        h = func.list_to_bytes(content)
        sm2_sign = sm2.CryptSM2(public_key=self.pub_key, private_key=self.pri_key)
        
        h_value ='%s' % h
        #print("\nsm3_sm2_signer message content1:")
        #print(h_value)
        
        signature = sm2_sign.sign_with_sm3(data=h)  
        para_len = len('FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFF7203DF6B21C6052B53BBF40939D54123')
        r = int(signature[0:para_len], 16)
        s = int(signature[para_len:2*para_len], 16)        
        sig_pair = (r, s)   
        
        sig_value ='%064x%064x' % (r, s)  
        #print("\nsm3_sm2_signer message sig_value1:") 
        #print(sig_value)   
        
        # if we use DER format of signature, the following comments can be used.
        output = DerSequence(sig_pair).encode()
        
        # if we use binary format of signature.
        #output = b"".join([long_to_bytes(x, 32)
        #                       for x in sig_pair])      
        real_len = len(output)
        wire[:real_len] = output
        return real_len

