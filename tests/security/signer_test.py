# -----------------------------------------------------------------------------
# Copyright (C) 2019-2020 The python-ndn authors
#
# This file is part of python-ndn.
#
# Modified by liupenghui, supports Sm3WithSm2Signer, and show how to use an existing asymmetric key in PIB to sign Data or Interest  
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
import base64
from Cryptodome.Util.asn1 import DerSequence
from Cryptodome.PublicKey import ECC
from ndn.encoding import make_data, make_interest, InterestParam, parse_interest, MetaInfo, parse_data, Name
from ndn.encoding.ndn_format_0_3 import get_data
from ndn.encoding.name.Name import to_str
from ndn.security.signer import Sha256WithEcdsaSigner, Sha256WithRsaSigner, HmacSha256Signer 
    
from ndn.security.validator.known_key_validator import SM2Checker, EccChecker, RsaChecker, HmacChecker     
from ndn.security.signer.sm3_sm2_signer import Sm3WithSm2Signer    
from ndn.security import sm2, sm3, func
from ndn.platform import Platform
from ndn.client_conf import default_keychain
from ndn.security.keychain import KeychainSqlite3
from Cryptodome.Math.Numbers import Integer
from Cryptodome.Random import get_random_bytes
from Cryptodome.Random.random import getrandbits
from Cryptodome.Util.py3compat import bord, tobytes, tostr, bchr, is_string
from Cryptodome.Util.asn1 import (DerObjectId, DerOctetString, DerSequence,
                              DerBitString)
from Cryptodome.IO import PKCS8                              
from Cryptodome.PublicKey import (_expand_subject_public_key_info,
                              _create_subject_public_key_info,
                              _extract_subject_public_key_info)
from Cryptodome.Util.number import long_to_bytes, bytes_to_long
                              
class TestSha256WithEcdsaSigner:
    def test_verify(self):
        # Ecdsa signature is not unique, so we only test if we can verify it
        pri_key = ECC.generate(curve="P-256")
        key = pri_key.export_key(format="DER")
        pub_key = pri_key.public_key()
        signer = Sha256WithEcdsaSigner("/K/KEY/x", key)
        pkt = make_data("/test", MetaInfo(), b"test content", signer=signer)
        _, _, _, sig_ptrs = parse_data(pkt)
        # Test its format is ASN.1 der format
        DerSequence().decode(bytes(sig_ptrs.signature_value_buf))
        validator = EccChecker.from_key("/K/KEY/x", bytes(pub_key.export_key(format='DER')))
        assert aio.run(validator(Name.from_str("/test"), sig_ptrs))

# Added by liupenghui to test Sm3WithSm2Signer
class TestSm3WithSm2Signer:
    def test_verify(self):
        # sm2 signature is not unique, so we only test if we can verify it
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
        para_len = len('FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFF7203DF6B21C6052B53BBF40939D54123')
        #print('\nsigner_test private key1:')
        #print(private_key)        
        # public_key= sG is a true public key.
        public_key = sm2_sign._kg(s, '32c4ae2c1f1981195f9904466a39c9948fe30bbff2660be1715a4589334c74c7bc3736a2f4f6779c59bdcee36b692153d0a9877cc62a474002df32e52139f0a0')
        px = int(public_key[0:para_len], 16)
        py = int(public_key[para_len:2 * para_len], 16)
        #print('\nsigner_test public_key key1:')
        #print(public_key)        
        
        #SEC1_public_key = (b'\x04' + px.to_bytes(para_len >> 1,'big') + py.to_bytes(para_len >> 1,'big'))
        SEC1_public_key = (b'\x04' + long_to_bytes(px, para_len >> 1) + long_to_bytes(py, para_len >> 1))
        unrestricted_oid = "1.2.840.10045.2.1"
        #pub_key and key_der format = 'DER', pri_key use_pkcs8=true
        pub_key = bytes(_create_subject_public_key_info(unrestricted_oid, SEC1_public_key, DerObjectId("1.2.156.10197.1.301")))        
        #seq = [1, DerOctetString(s.to_bytes(para_len >> 1,'big')), DerObjectId("1.2.840.10045.3.1.7", explicit=0), DerBitString(SEC1_public_key, explicit=1)]  
        seq = [1, DerOctetString(long_to_bytes(s, para_len >> 1)), DerObjectId("1.2.156.10197.1.301", explicit=0), DerBitString(SEC1_public_key, explicit=1)]  
                
        print("sm2:%s" % DerObjectId("1.2.156.10197.1.301").encode().hex())
        print("ecdsa:%s" % DerObjectId("1.2.840.10045.3.1.7").encode().hex())        
        print("unrestricted_oid:%s" % DerObjectId("1.2.840.10045.2.1").encode().hex()) 
        
        del seq[2]
        enc_private_key = DerSequence(seq).encode()            
        
        key_der = PKCS8.wrap(enc_private_key,
                            unrestricted_oid,
                            key_params=DerObjectId("1.2.156.10197.1.301"))        
        signer = Sm3WithSm2Signer("/K/KEY/x", key_der)
        pkt = make_data("/test", MetaInfo(), b"test content", signer=signer)
        _, _, _, sig_ptrs = parse_data(pkt)
        # Test whether its format is ASN.1 der format or not
        # Currently we use binary signature, so no need to test the DER format of signature
        # DerSequence().decode(bytes(sig_ptrs.signature_value_buf))
        
        # Below section is used for debug start ----------------------------------------------------------------------------------
        encoded = tobytes(key_der)
        algo_oid, enc_private_key, params = PKCS8.unwrap(encoded, None)
        curve_oid = DerObjectId().decode(params).value
        private_key = DerSequence().decode(enc_private_key, nr_elements=(3, 4))
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
        #print('\nsigner_test private key2:')
        #print(pri_key)
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
            pub_key1 = form % (x, y)   
            
        #print("\nsigner_test verify_public1:")
        #print(pub_key1)
        #debug end -------------------------------------------------------------------------------------------------
        
        
        validator = SM2Checker.from_key("/K/KEY/x", pub_key)
        assert aio.run(validator(Name.from_str("/test"), sig_ptrs))

class TestSha256WithHmacSigner:
    def test_rfc4231_1(self):
        key = b'\x0b' * 20
        signer = HmacSha256Signer('name', key)
        data = b'Hi There'
        wire = bytearray(32)
        assert signer.get_signature_value_size() == 32
        assert signer.write_signature_value(wire, [memoryview(data)]) == 32
        assert wire.hex() == 'b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7'

    def test_rfc4231_2(self):
        key = b'Jefe'
        signer = HmacSha256Signer('name', key)
        data = b'what do ya want for nothing?'
        wire = bytearray(32)
        assert signer.write_signature_value(wire, [memoryview(data)]) == 32
        assert wire.hex() == '5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843'

    def test_rfc4231_3(self):
        key = b'\xaa' * 20
        signer = HmacSha256Signer('name', key)
        data = b'\xdd' * 50
        wire = bytearray(32)
        assert signer.write_signature_value(wire, [memoryview(data)]) == 32
        assert wire.hex() == '773ea91e36800e46854db8ebd09181a72959098b3ef8c122d9635514ced565fe'

    def test_data_1(self):
        key = bytes(i for i in range(32))
        signer = HmacSha256Signer('key1', key)
        data = make_data('/ndn/abc', MetaInfo(None), b'SUCCESS!', signer)
        assert (data.hex() == '0649070a08036e646e0803616263'
                              '140015085355434345535321'
                              '160d1b01041c08070608046b657931'
                              '172019868e7183998df373332f3dd1c9c950fc29d734c07977791d8396fa3b91fd36')
        _, _, _, sig_ptrs = parse_data(data)
        validator = HmacChecker.from_key('key1', key)
        assert aio.run(validator(Name.from_str('/ndn/abc'), sig_ptrs))


class TestSha256WithRsaSigner:
    def test_data(self):
        key = bytes([
            0x30, 0x82, 0x04, 0xbf, 0x02, 0x01, 0x00, 0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7,
            0x0d, 0x01, 0x01, 0x01, 0x05, 0x00, 0x04, 0x82, 0x04, 0xa9, 0x30, 0x82, 0x04, 0xa5, 0x02, 0x01,
            0x00, 0x02, 0x82, 0x01, 0x01, 0x00, 0xb8, 0x09, 0xa7, 0x59, 0x82, 0x84, 0xec, 0x4f, 0x06, 0xfa,
            0x1c, 0xb2, 0xe1, 0x38, 0x93, 0x53, 0xbb, 0x7d, 0xd4, 0xac, 0x88, 0x1a, 0xf8, 0x25, 0x11, 0xe4,
            0xfa, 0x1d, 0x61, 0x24, 0x5b, 0x82, 0xca, 0xcd, 0x72, 0xce, 0xdb, 0x66, 0xb5, 0x8d, 0x54, 0xbd,
            0xfb, 0x23, 0xfd, 0xe8, 0x8e, 0xaf, 0xa7, 0xb3, 0x79, 0xbe, 0x94, 0xb5, 0xb7, 0xba, 0x17, 0xb6,
            0x05, 0xae, 0xce, 0x43, 0xbe, 0x3b, 0xce, 0x6e, 0xea, 0x07, 0xdb, 0xbf, 0x0a, 0x7e, 0xeb, 0xbc,
            0xc9, 0x7b, 0x62, 0x3c, 0xf5, 0xe1, 0xce, 0xe1, 0xd9, 0x8d, 0x9c, 0xfe, 0x1f, 0xc7, 0xf8, 0xfb,
            0x59, 0xc0, 0x94, 0x0b, 0x2c, 0xd9, 0x7d, 0xbc, 0x96, 0xeb, 0xb8, 0x79, 0x22, 0x8a, 0x2e, 0xa0,
            0x12, 0x1d, 0x42, 0x07, 0xb6, 0x5d, 0xdb, 0xe1, 0xf6, 0xb1, 0x5d, 0x7b, 0x1f, 0x54, 0x52, 0x1c,
            0xa3, 0x11, 0x9b, 0xf9, 0xeb, 0xbe, 0xb3, 0x95, 0xca, 0xa5, 0x87, 0x3f, 0x31, 0x18, 0x1a, 0xc9,
            0x99, 0x01, 0xec, 0xaa, 0x90, 0xfd, 0x8a, 0x36, 0x35, 0x5e, 0x12, 0x81, 0xbe, 0x84, 0x88, 0xa1,
            0x0d, 0x19, 0x2a, 0x4a, 0x66, 0xc1, 0x59, 0x3c, 0x41, 0x83, 0x3d, 0x3d, 0xb8, 0xd4, 0xab, 0x34,
            0x90, 0x06, 0x3e, 0x1a, 0x61, 0x74, 0xbe, 0x04, 0xf5, 0x7a, 0x69, 0x1b, 0x9d, 0x56, 0xfc, 0x83,
            0xb7, 0x60, 0xc1, 0x5e, 0x9d, 0x85, 0x34, 0xfd, 0x02, 0x1a, 0xba, 0x2c, 0x09, 0x72, 0xa7, 0x4a,
            0x5e, 0x18, 0xbf, 0xc0, 0x58, 0xa7, 0x49, 0x34, 0x46, 0x61, 0x59, 0x0e, 0xe2, 0x6e, 0x9e, 0xd2,
            0xdb, 0xfd, 0x72, 0x2f, 0x3c, 0x47, 0xcc, 0x5f, 0x99, 0x62, 0xee, 0x0d, 0xf3, 0x1f, 0x30, 0x25,
            0x20, 0x92, 0x15, 0x4b, 0x04, 0xfe, 0x15, 0x19, 0x1d, 0xdc, 0x7e, 0x5c, 0x10, 0x21, 0x52, 0x21,
            0x91, 0x54, 0x60, 0x8b, 0x92, 0x41, 0x02, 0x03, 0x01, 0x00, 0x01, 0x02, 0x82, 0x01, 0x01, 0x00,
            0x8a, 0x05, 0xfb, 0x73, 0x7f, 0x16, 0xaf, 0x9f, 0xa9, 0x4c, 0xe5, 0x3f, 0x26, 0xf8, 0x66, 0x4d,
            0xd2, 0xfc, 0xd1, 0x06, 0xc0, 0x60, 0xf1, 0x9f, 0xe3, 0xa6, 0xc6, 0x0a, 0x48, 0xb3, 0x9a, 0xca,
            0x21, 0xcd, 0x29, 0x80, 0x88, 0x3d, 0xa4, 0x85, 0xa5, 0x7b, 0x82, 0x21, 0x81, 0x28, 0xeb, 0xf2,
            0x43, 0x24, 0xb0, 0x76, 0xc5, 0x52, 0xef, 0xc2, 0xea, 0x4b, 0x82, 0x41, 0x92, 0xc2, 0x6d, 0xa6,
            0xae, 0xf0, 0xb2, 0x26, 0x48, 0xa1, 0x23, 0x7f, 0x02, 0xcf, 0xa8, 0x90, 0x17, 0xa2, 0x3e, 0x8a,
            0x26, 0xbd, 0x6d, 0x8a, 0xee, 0xa6, 0x0c, 0x31, 0xce, 0xc2, 0xbb, 0x92, 0x59, 0xb5, 0x73, 0xe2,
            0x7d, 0x91, 0x75, 0xe2, 0xbd, 0x8c, 0x63, 0xe2, 0x1c, 0x8b, 0xc2, 0x6a, 0x1c, 0xfe, 0x69, 0xc0,
            0x44, 0xcb, 0x58, 0x57, 0xb7, 0x13, 0x42, 0xf0, 0xdb, 0x50, 0x4c, 0xe0, 0x45, 0x09, 0x8f, 0xca,
            0x45, 0x8a, 0x06, 0xfe, 0x98, 0xd1, 0x22, 0xf5, 0x5a, 0x9a, 0xdf, 0x89, 0x17, 0xca, 0x20, 0xcc,
            0x12, 0xa9, 0x09, 0x3d, 0xd5, 0xf7, 0xe3, 0xeb, 0x08, 0x4a, 0xc4, 0x12, 0xc0, 0xb9, 0x47, 0x6c,
            0x79, 0x50, 0x66, 0xa3, 0xf8, 0xaf, 0x2c, 0xfa, 0xb4, 0x6b, 0xec, 0x03, 0xad, 0xcb, 0xda, 0x24,
            0x0c, 0x52, 0x07, 0x87, 0x88, 0xc0, 0x21, 0xf3, 0x02, 0xe8, 0x24, 0x44, 0x0f, 0xcd, 0xa0, 0xad,
            0x2f, 0x1b, 0x79, 0xab, 0x6b, 0x49, 0x4a, 0xe6, 0x3b, 0xd0, 0xad, 0xc3, 0x48, 0xb9, 0xf7, 0xf1,
            0x34, 0x09, 0xeb, 0x7a, 0xc0, 0xd5, 0x0d, 0x39, 0xd8, 0x45, 0xce, 0x36, 0x7a, 0xd8, 0xde, 0x3c,
            0xb0, 0x21, 0x96, 0x97, 0x8a, 0xff, 0x8b, 0x23, 0x60, 0x4f, 0xf0, 0x3d, 0xd7, 0x8f, 0xf3, 0x2c,
            0xcb, 0x1d, 0x48, 0x3f, 0x86, 0xc4, 0xa9, 0x00, 0xf2, 0x23, 0x2d, 0x72, 0x4d, 0x66, 0xa5, 0x01,
            0x02, 0x81, 0x81, 0x00, 0xdc, 0x4f, 0x99, 0x44, 0x0d, 0x7f, 0x59, 0x46, 0x1e, 0x8f, 0xe7, 0x2d,
            0x8d, 0xdd, 0x54, 0xc0, 0xf7, 0xfa, 0x46, 0x0d, 0x9d, 0x35, 0x03, 0xf1, 0x7c, 0x12, 0xf3, 0x5a,
            0x9d, 0x83, 0xcf, 0xdd, 0x37, 0x21, 0x7c, 0xb7, 0xee, 0xc3, 0x39, 0xd2, 0x75, 0x8f, 0xb2, 0x2d,
            0x6f, 0xec, 0xc6, 0x03, 0x55, 0xd7, 0x00, 0x67, 0xd3, 0x9b, 0xa2, 0x68, 0x50, 0x6f, 0x9e, 0x28,
            0xa4, 0x76, 0x39, 0x2b, 0xb2, 0x65, 0xcc, 0x72, 0x82, 0x93, 0xa0, 0xcf, 0x10, 0x05, 0x6a, 0x75,
            0xca, 0x85, 0x35, 0x99, 0xb0, 0xa6, 0xc6, 0xef, 0x4c, 0x4d, 0x99, 0x7d, 0x2c, 0x38, 0x01, 0x21,
            0xb5, 0x31, 0xac, 0x80, 0x54, 0xc4, 0x18, 0x4b, 0xfd, 0xef, 0xb3, 0x30, 0x22, 0x51, 0x5a, 0xea,
            0x7d, 0x9b, 0xb2, 0x9d, 0xcb, 0xba, 0x3f, 0xc0, 0x1a, 0x6b, 0xcd, 0xb0, 0xe6, 0x2f, 0x04, 0x33,
            0xd7, 0x3a, 0x49, 0x71, 0x02, 0x81, 0x81, 0x00, 0xd5, 0xd9, 0xc9, 0x70, 0x1a, 0x13, 0xb3, 0x39,
            0x24, 0x02, 0xee, 0xb0, 0xbb, 0x84, 0x17, 0x12, 0xc6, 0xbd, 0x65, 0x73, 0xe9, 0x34, 0x5d, 0x43,
            0xff, 0xdc, 0xf8, 0x55, 0xaf, 0x2a, 0xb9, 0xe1, 0xfa, 0x71, 0x65, 0x4e, 0x50, 0x0f, 0xa4, 0x3b,
            0xe5, 0x68, 0xf2, 0x49, 0x71, 0xaf, 0x15, 0x88, 0xd7, 0xaf, 0xc4, 0x9d, 0x94, 0x84, 0x6b, 0x5b,
            0x10, 0xd5, 0xc0, 0xaa, 0x0c, 0x13, 0x62, 0x99, 0xc0, 0x8b, 0xfc, 0x90, 0x0f, 0x87, 0x40, 0x4d,
            0x58, 0x88, 0xbd, 0xe2, 0xba, 0x3e, 0x7e, 0x2d, 0xd7, 0x69, 0xa9, 0x3c, 0x09, 0x64, 0x31, 0xb6,
            0xcc, 0x4d, 0x1f, 0x23, 0xb6, 0x9e, 0x65, 0xd6, 0x81, 0xdc, 0x85, 0xcc, 0x1e, 0xf1, 0x0b, 0x84,
            0x38, 0xab, 0x93, 0x5f, 0x9f, 0x92, 0x4e, 0x93, 0x46, 0x95, 0x6b, 0x3e, 0xb6, 0xc3, 0x1b, 0xd7,
            0x69, 0xa1, 0x0a, 0x97, 0x37, 0x78, 0xed, 0xd1, 0x02, 0x81, 0x80, 0x33, 0x18, 0xc3, 0x13, 0x65,
            0x8e, 0x03, 0xc6, 0x9f, 0x90, 0x00, 0xae, 0x30, 0x19, 0x05, 0x6f, 0x3c, 0x14, 0x6f, 0xea, 0xf8,
            0x6b, 0x33, 0x5e, 0xee, 0xc7, 0xf6, 0x69, 0x2d, 0xdf, 0x44, 0x76, 0xaa, 0x32, 0xba, 0x1a, 0x6e,
            0xe6, 0x18, 0xa3, 0x17, 0x61, 0x1c, 0x92, 0x2d, 0x43, 0x5d, 0x29, 0xa8, 0xdf, 0x14, 0xd8, 0xff,
            0xdb, 0x38, 0xef, 0xb8, 0xb8, 0x2a, 0x96, 0x82, 0x8e, 0x68, 0xf4, 0x19, 0x8c, 0x42, 0xbe, 0xcc,
            0x4a, 0x31, 0x21, 0xd5, 0x35, 0x6c, 0x5b, 0xa5, 0x7c, 0xff, 0xd1, 0x85, 0x87, 0x28, 0xdc, 0x97,
            0x75, 0xe8, 0x03, 0x80, 0x1d, 0xfd, 0x25, 0x34, 0x41, 0x31, 0x21, 0x12, 0x87, 0xe8, 0x9a, 0xb7,
            0x6a, 0xc0, 0xc4, 0x89, 0x31, 0x15, 0x45, 0x0d, 0x9c, 0xee, 0xf0, 0x6a, 0x2f, 0xe8, 0x59, 0x45,
            0xc7, 0x7b, 0x0d, 0x6c, 0x55, 0xbb, 0x43, 0xca, 0xc7, 0x5a, 0x01, 0x02, 0x81, 0x81, 0x00, 0xab,
            0xf4, 0xd5, 0xcf, 0x78, 0x88, 0x82, 0xc2, 0xdd, 0xbc, 0x25, 0xe6, 0xa2, 0xc1, 0xd2, 0x33, 0xdc,
            0xef, 0x0a, 0x97, 0x2b, 0xdc, 0x59, 0x6a, 0x86, 0x61, 0x4e, 0xa6, 0xc7, 0x95, 0x99, 0xa6, 0xa6,
            0x55, 0x6c, 0x5a, 0x8e, 0x72, 0x25, 0x63, 0xac, 0x52, 0xb9, 0x10, 0x69, 0x83, 0x99, 0xd3, 0x51,
            0x6c, 0x1a, 0xb3, 0x83, 0x6a, 0xff, 0x50, 0x58, 0xb7, 0x28, 0x97, 0x13, 0xe2, 0xba, 0x94, 0x5b,
            0x89, 0xb4, 0xea, 0xba, 0x31, 0xcd, 0x78, 0xe4, 0x4a, 0x00, 0x36, 0x42, 0x00, 0x62, 0x41, 0xc6,
            0x47, 0x46, 0x37, 0xea, 0x6d, 0x50, 0xb4, 0x66, 0x8f, 0x55, 0x0c, 0xc8, 0x99, 0x91, 0xd5, 0xec,
            0xd2, 0x40, 0x1c, 0x24, 0x7d, 0x3a, 0xff, 0x74, 0xfa, 0x32, 0x24, 0xe0, 0x11, 0x2b, 0x71, 0xad,
            0x7e, 0x14, 0xa0, 0x77, 0x21, 0x68, 0x4f, 0xcc, 0xb6, 0x1b, 0xe8, 0x00, 0x49, 0x13, 0x21, 0x02,
            0x81, 0x81, 0x00, 0xb6, 0x18, 0x73, 0x59, 0x2c, 0x4f, 0x92, 0xac, 0xa2, 0x2e, 0x5f, 0xb6, 0xbe,
            0x78, 0x5d, 0x47, 0x71, 0x04, 0x92, 0xf0, 0xd7, 0xe8, 0xc5, 0x7a, 0x84, 0x6b, 0xb8, 0xb4, 0x30,
            0x1f, 0xd8, 0x0d, 0x58, 0xd0, 0x64, 0x80, 0xa7, 0x21, 0x1a, 0x48, 0x00, 0x37, 0xd6, 0x19, 0x71,
            0xbb, 0x91, 0x20, 0x9d, 0xe2, 0xc3, 0xec, 0xdb, 0x36, 0x1c, 0xca, 0x48, 0x7d, 0x03, 0x32, 0x74,
            0x1e, 0x65, 0x73, 0x02, 0x90, 0x73, 0xd8, 0x3f, 0xb5, 0x52, 0x35, 0x79, 0x1c, 0xee, 0x93, 0xa3,
            0x32, 0x8b, 0xed, 0x89, 0x98, 0xf1, 0x0c, 0xd8, 0x12, 0xf2, 0x89, 0x7f, 0x32, 0x23, 0xec, 0x67,
            0x66, 0x52, 0x83, 0x89, 0x99, 0x5e, 0x42, 0x2b, 0x42, 0x4b, 0x84, 0x50, 0x1b, 0x3e, 0x47, 0x6d,
            0x74, 0xfb, 0xd1, 0xa6, 0x10, 0x20, 0x6c, 0x6e, 0xbe, 0x44, 0x3f, 0xb9, 0xfe, 0xbc, 0x8d, 0xda,
            0xcb, 0xea, 0x8f
        ])
        meta_info = MetaInfo(None, 5000, b'\x08\x02\x00\x09')
        signer = Sha256WithRsaSigner('/testname/KEY/123', key)
        data = make_data('/ndn/abc', meta_info, b'SUCCESS!', signer)
        assert (data.hex() == '06fd0143070a08036e646e0803616263'
                              '140a190213881a0408020009'
                              '15085355434345535321'
                              '161b1b01011c1607140808746573746e616d6508034b45590803313233'
                              '17fd0100'
                              '5716f5b96a3141dba78970efa4f45601a36c2fc9910e82292c321ae6672ee099'
                              '44930ef3dab60d714927a87063f1b8382d6c98c894cf2f065d7da28b380fa6cd'
                              '08c83a243d847bc086da99c85fd14e941593d16e4f060b6a3bffb98035900643'
                              '0ac22a334cb37dce105902e86ee8c7f4363042bdb815b455d0ce62ae7c43b027'
                              '9842dd956f67a696ee176415873c918f36d976d68971d8d7f903a71ef6f38b27'
                              '3c0d8ccfe23f12ecf5212a34b94eb62f822cda1f09e0f949640319cd026fb1ab'
                              '85282e30a8fe3899bc86d86696e11e157b74f88c0efd9823369dab63262f5d7a'
                              'abb372a3aaf43307331a2796e913e3d36150f6a387b4c97c19a493bb4513af3f')
        validator = RsaChecker.from_key('/testname/KEY/123', key)
        _, _, _, sig_ptrs = parse_data(data)
        assert aio.run(validator(Name.from_str('/ndn/abc'), sig_ptrs))
        
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

# Test Sign a Data With SM2 Key in PIB.
class TestSignDataWithSM2KeyName:
    def test_data(self):
        # sign Data with a existed key named('/mytest1/KEY/%82%D2%3E~%09%11N%DB'), key_type='sm2'  
        # please confirm your PIB has this named asymmetric sm2 key (/mytest1/KEY/%82%D2%3E~%09%11N%DB) using command pyndnsec list -vvv or ndnsec list -vvv
        key_name= "/mytest1/KEY/%82%D2%3E~%09%11N%DB"
        key_type= 'sm2'
        kc = GetKeyChain()
        key_type = kc.get_key_type(key_name);
        assert key_type == 'sm2'
        key_name = Name.normalize(key_name)
        #print(to_str(key_name))
        signer = kc.tpm.get_signer(key_name, key_type)
        pktbuf, pkt = get_data("/test", MetaInfo(), b"test content", signer=signer)

        print("")
        print("The SM2 signed data packet original bytes:")
        pktb = bytes(pktbuf)
        print(pktb.hex())
        
        print("")
        print("The SM2 signed data packet base64:")
        text = base64.standard_b64encode(bytes(pkt)).decode()
        cnt = (len(text) + 63) // 64
        for i in range(cnt):
            print(text[i * 64:(i + 1) * 64])
        print("")
        
        print("pub_key:%s" % signer.pub_key)         
        _, _, _, sig_ptrs = parse_data(pkt)
        
        print("")
        print("sig_ptrs.signature_covered_part:")
        scp = bytes(sig_ptrs.signature_covered_part[0])
        print(scp.hex())        
        
        print("") 
        print(len(sig_ptrs.signature_value_buf))
        print("sig_ptrs.signature_value_buf:%s" % sig_ptrs.signature_value_buf.hex())
        
        # Test its format is ASN.1 der format
        validator = SM2Checker.from_key("/mytest1/KEY/%82%D2%3E~%09%11N%DB", GetPublicBytes(signer.pub_key))
        assert aio.run(validator(Name.from_str("/test"), sig_ptrs)) 

# Test Sign a Interest With SM2 Key in PIB.
class TestSignInterestWithSM2KeyName:
    def test_data(self):
        # sign Interest with a existed key named('/ndn-pcnl-test/a/g/KEY/%15%FB%947%5B%98%11%2B'), key_type='sm2'  
        # please confirm your PIB has this named asymmetric sm2 key (/ndn-pcnl-test/a/g/KEY/%15%FB%947%5B%98%11%2B) using command pyndnsec list -vvv or ndnsec list -vvv
        key_name= "/ndn-pcnl-test/a/g/KEY/%15%FB%947%5B%98%11%2B"
        key_type= 'sm2'
        kc = GetKeyChain()
        key_type = kc.get_key_type(key_name);
        assert key_type == 'sm2'        
        key_name = Name.normalize(key_name)
        #print(to_str(key_name))
        signer = kc.tpm.get_signer(key_name, key_type)
        pkt = make_interest("/test", InterestParam(), b"test content", signer=signer)
        _, _, _, sig_ptrs = parse_interest(pkt)
        # Test its format is ASN.1 der format
        validator = SM2Checker.from_key("/ndn-pcnl-test/a/g/KEY/%15%FB%947%5B%98%11%2B", GetPublicBytes(signer.pub_key))
        assert aio.run(validator(Name.from_str("/test"), sig_ptrs)) 
 
# Test Sign a Data With ECDSA Key in PIB.
class TestSignDataWithECDSAKeyName:
    def test_data(self):
        # sign Data with a existed key named('/mytest2/KEY/%CA%0C%C9%1FY%8E%3C%E0'), key_type='ec'  
        # please confirm your PIB has this named asymmetric ECDSA key (/mytest2/KEY/%CA%0C%C9%1FY%8E%3C%E0) using command pyndnsec list -vvv or ndnsec list -vvv
        key_name= "/mytest2/KEY/%CA%0C%C9%1FY%8E%3C%E0"
        key_type= 'ec'
        kc = GetKeyChain()
        key_type = kc.get_key_type(key_name);
        assert key_type == 'ec'           
        key_name = Name.normalize(key_name)
        #print(to_str(key_name))
        signer = kc.tpm.get_signer(key_name, key_type)
        _, pub_key, _ = kc.tpm.get_pulic_private_keys(key_name, key_type)
        pkt = make_data("/test", MetaInfo(), b"test content", signer=signer)
        
        print("")
        print("The ECDSA signed data packet base64:")
        text = base64.standard_b64encode(bytes(pkt)).decode()
        cnt = (len(text) + 63) // 64
        for i in range(cnt):
            print(text[i * 64:(i + 1) * 64])
        print("")
        
        _, _, _, sig_ptrs = parse_data(pkt)
        validator = EccChecker.from_key("/mytest2/KEY/%CA%0C%C9%1FY%8E%3C%E0", GetPublicBytes(pub_key))
        assert aio.run(validator(Name.from_str("/test"), sig_ptrs))       

# Test Sign a Interest With ECDSA Key in PIB.
class TestSignInterestWithECDSAKeyName:
    def test_data(self):
        # sign Interest with a existed key named('/mytest2/KEY/%CA%0C%C9%1FY%8E%3C%E0'), key_type='ec'  
        # please confirm your PIB has this named asymmetric ECDSA key (/mytest2/KEY/%CA%0C%C9%1FY%8E%3C%E0) using command pyndnsec list -vvv or ndnsec list -vvv
        key_name= "/mytest2/KEY/%CA%0C%C9%1FY%8E%3C%E0"
        key_type= 'ec'
        kc = GetKeyChain()
        key_type = kc.get_key_type(key_name);
        assert key_type == 'ec'           
        key_name = Name.normalize(key_name)
        #print(to_str(key_name))
        signer = kc.tpm.get_signer(key_name, key_type)
        _, pub_key, _ = kc.tpm.get_pulic_private_keys(key_name, key_type)
        pkt = make_interest("/test", InterestParam(), b"test content", signer=signer)
        _, _, _, sig_ptrs = parse_interest(pkt)
        validator = EccChecker.from_key("/mytest2/KEY/%CA%0C%C9%1FY%8E%3C%E0", GetPublicBytes(pub_key))
        assert aio.run(validator(Name.from_str("/test"), sig_ptrs)) 

# Test Sign a Data With RSA Key in PIB.
class TestSignDataWithRSAKeyName:
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
        signer = kc.tpm.get_signer(key_name, key_type)
        _, pub_key, key_der = kc.tpm.get_pulic_private_keys(key_name, key_type)
        pkt = make_data("/test", MetaInfo(), b"test content", signer=signer)
        _, _, _, sig_ptrs = parse_data(pkt)
        validator = RsaChecker.from_key("/mytest3/KEY/ezu%3AJ%26%2A%15", key_der)
        assert aio.run(validator(Name.from_str("/test"), sig_ptrs))   

# Test Sign a Interest With RSA Key in PIB.
class TestSignInterestWithRSAKeyName:
    def test_data(self):
        # sign Interest with a existed key named('/mytest3/KEY/ezu%3AJ%26%2A%15'), key_type='rsa'  
        # please confirm your PIB has this named asymmetric RSA key (/mytest3/KEY/ezu%3AJ%26%2A%15) using command pyndnsec list -vvv or ndnsec list -vvv
        key_name= "/mytest3/KEY/ezu%3AJ%26%2A%15"
        key_type= 'rsa'
        kc = GetKeyChain()
        key_type = kc.get_key_type(key_name);
        assert key_type == 'rsa'           
        key_name = Name.normalize(key_name)
        #print(to_str(key_name))
        signer = kc.tpm.get_signer(key_name, key_type)
        _, pub_key, key_der = kc.tpm.get_pulic_private_keys(key_name, key_type)
        pkt = make_interest("/test", InterestParam(), b"test content", signer=signer)
        _, _, _, sig_ptrs = parse_interest(pkt)
        validator = RsaChecker.from_key("/mytest3/KEY/ezu%3AJ%26%2A%15", key_der)
        assert aio.run(validator(Name.from_str("/test"), sig_ptrs))  
 
def main():
    test1 = TestSha256WithEcdsaSigner()
    test1.test_verify()
    print("TestSha256WithEcdsaSigner OK!")

    test1 = TestSm3WithSm2Signer()
    test1.test_verify()
    print("TestSm3WithSm2Signer OK!")
  
    test1 = TestSha256WithHmacSigner()
    test1.test_rfc4231_1()
    print("Test_rfc4231_1 in TestSha256WithHmacSigner OK!")

    test1.test_rfc4231_2()
    print("Test_rfc4231_2 in TestSha256WithHmacSigner OK!")
    
    test1.test_rfc4231_3()
    print("Test_rfc4231_3 in TestSha256WithHmacSigner OK!")    

    test1.test_data_1()
    print("Test_data_1 in TestSha256WithHmacSigner OK!")    
 
    test1 = TestSha256WithRsaSigner()
    test1.test_data()
    print("TestSha256WithRsaSigner OK!")    
    
    test1 = TestSignDataWithSM2KeyName()
    test1.test_data() 
    print("TestSignDataWithSM2KeyName OK!")    

    test1 = TestSignInterestWithSM2KeyName()
    test1.test_data() 
    print("TestSignInterestWithSM2KeyName OK!")    

    test1 = TestSignDataWithECDSAKeyName()
    test1.test_data() 
    print("TestSignDataWithECDSAKeyName OK!")  

    test1 = TestSignInterestWithECDSAKeyName()
    test1.test_data() 
    print("TestSignInterestWithECDSAKeyName OK!")  

    test1 = TestSignDataWithRSAKeyName()
    test1.test_data() 
    print("TestSignDataWithRSAKeyName OK!")  
 
    test1 = TestSignInterestWithRSAKeyName()
    test1.test_data() 
    print("TestSignInterestWithRSAKeyName OK!")  
    
if __name__ == '__main__':
    main()
