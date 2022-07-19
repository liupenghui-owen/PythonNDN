# -----------------------------------------------------------------------------
# Copyright (C) 2019-2021 The python-ndn authors
#
# This file is part of python-ndn. 
#
# Created by liupenghui to import a key/certificate safbag 
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
import argparse
from base64 import b64decode, b64encode
import os
from .utils import resolve_keychain, get_default_cert,infer_obj_name
from ...encoding import Name, FormalName, SignatureType
from ...security.safbag import encode_encrypted_key, make_safebag, parse_safebag
from Cryptodome.PublicKey import RSA, ECC
from Cryptodome.PublicKey import _create_subject_public_key_info
from Cryptodome.Util.asn1 import (DerObjectId, DerOctetString, DerSequence,
                              DerBitString)
from Cryptodome.Util.number import long_to_bytes, bytes_to_long
from Cryptodome.IO import PKCS8
from Cryptodome.Util.py3compat import tobytes, bord, tostr
from Cryptodome.Math.Numbers import Integer
from ...app_support.security_v2 import parse_certificate
                              
def add_parser(subparsers):
    parser = subparsers.add_parser('Import-key', aliases=['importkey', 'ik', 'import-key'])
    parser.add_argument('file', metavar='FILE', 
                        help="file name of the certificate to be imported")                        
    parser.set_defaults(executor=execute)


def execute(args: argparse.Namespace):
    kc = resolve_keychain(args)
    file_name = os.path.expandvars(args.file)
    if not os.path.exists(file_name):
        raise ValueError("File don't exist.")
    with open(file_name, 'rb') as f:
        safbag_b64 = f.read()
    safbag = tobytes(b64decode(safbag_b64))
    cert_data, encrypted_key = parse_safebag(safbag)
    try:
        cert = parse_certificate(cert_data)
    except (ValueError, IndexError):
        print('Malformed certificate')
        return -1 
        
    key_type = 'ec'    
    if cert.signature_info.signature_type == SignatureType.SHA256_WITH_RSA:
        key_type = 'rsa' 
    elif cert.signature_info.signature_type == SignatureType.SHA256_WITH_ECDSA:    
        key_type = 'ec' 
    elif cert.signature_info.signature_type == SignatureType.SM3_WITH_SM2: 
        key_type = 'sm2'  
    else:
        print('Malformed certificate, signature_type error ')
        return -1   

    passphrase = b''    
    passphrase0 = input("Passphrase for the private key: ")
    passphrase = tobytes(passphrase0)
 
    if key_type == 'sm2' or key_type == 'ec':
        encrypted_key = tobytes(encrypted_key)
        algo_oid, enc_private_key, params = PKCS8.unwrap(encrypted_key, passphrase)
        private_key = DerSequence().decode(enc_private_key, nr_elements=(3, 4))
        if private_key[0] != 1:
            raise ValueError("Incorrect private key version")

        scalar_bytes = DerOctetString().decode(private_key[1]).payload
        modulus_bytes = 32
        if len(scalar_bytes) != modulus_bytes:
            raise ValueError("Private key is too small")
        d = Integer(bytes_to_long(scalar_bytes))
        para_len = len('FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFF7203DF6B21C6052B53BBF40939D54123')
        if len(private_key) == 3:
            public_key_enc = DerBitString(explicit=1).decode(private_key[2]).value
            if len(public_key_enc) != (1 + 2 * modulus_bytes):
                raise ValueError("Incorrect EC point length")
            x = Integer(bytes_to_long(public_key_enc[1:modulus_bytes+1]))
            y = Integer(bytes_to_long(public_key_enc[modulus_bytes+1:]))                                          
        else:
            raise ValueError("No pkcs8 point x, y found")  
        SEC1_public_key = (b'\x04' + long_to_bytes(x, para_len >> 1) + long_to_bytes(y, para_len >> 1))
        unrestricted_oid = "1.2.840.10045.2.1"
        ObjectId = "1.2.840.10045.3.1.7"
        if key_type == 'sm2':
            ObjectId = "1.2.156.10197.1.301"        
        pub_key = bytes(_create_subject_public_key_info(unrestricted_oid, SEC1_public_key, DerObjectId(ObjectId)))    
        seq = [1, DerOctetString(long_to_bytes(d, para_len >> 1)), DerObjectId(ObjectId, explicit=0), DerBitString(SEC1_public_key, explicit=1)]  
        key_der = DerSequence(seq).encode()  
        
    else:
        #rsa
        encrypted_key = tobytes(encrypted_key)
        rsa_key = RSA.import_key(encrypted_key, passphrase)
        pub_key = bytes(rsa_key.public_key().export_key(format='DER'))
        key_der = rsa_key.export_key(format='DER', pkcs=1)
        
    cert_name = Name.normalize(cert.name)
    key_name = Name.normalize(cert_name[:-2])
    id_name = Name.normalize(cert_name[:-4])
    
    #print(Name.to_str(cert_name))
    #print(Name.to_str(key_name))
    #print(Name.to_str(id_name))
    
    kc.tpm.save_key(key_name, key_der)       
    kc.import_key(id_name, key_name, key_type, pub_key)
    try:
        key = kc[id_name][key_name]
    except KeyError:
        print(f'Private key {Name.to_str(key_name)} does not exist.')
        return -2
    try:
        _ = key[cert_name]
        print(f'certificate {Name.to_str(cert_name)} already exists.')
        return -2
    except KeyError:
        pass
    kc.import_cert(key_name, cert_name, cert_data)    
 
