# -----------------------------------------------------------------------------
# Copyright (C) 2019-2021 The python-ndn authors
#
# This file is part of python-ndn. 
#
# Created by liupenghui to export key/certificate safbag
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
from .utils import resolve_keychain, get_default_cert
from ...encoding import Name, FormalName
from ...security.safbag import encode_encrypted_key, make_safebag
from Cryptodome.PublicKey import RSA, ECC
from Cryptodome.Util.asn1 import (DerObjectId, DerOctetString, DerSequence,
                              DerBitString)
from Cryptodome.Util.number import long_to_bytes, bytes_to_long
from Cryptodome.IO import PKCS8
from Cryptodome.Util.py3compat import tobytes, bord, tostr
from Cryptodome.Math.Numbers import Integer
                              
def add_parser(subparsers):
    parser = subparsers.add_parser('Export-key', aliases=['exportkey', 'ek', 'export-key'])
    parser.add_argument('obj', metavar='KeyName', 
                        help='name of the key to export.')
    parser.add_argument('file', metavar='FILE', 
                        help="file name of the certificate to be imported")                        
    parser.set_defaults(executor=execute)


def execute(args: argparse.Namespace):
    kc = resolve_keychain(args)
    cert = get_default_cert(kc, args)
    if cert is None:
        return -2
        
    obj = args.obj
    if obj:
        key_name = Name.from_str(obj)
    else:
        return -2
        
    passphrase = b''
    
    while True:
        passphrase0 = input("Passphrase for the private key: ")
        passphrase1 = input("Confirm：")
        if passphrase0 == passphrase1:
            passphrase = tobytes(passphrase0)
            break;
        
    key_type = kc.get_key_type(key_name);   
    key_name = Name.normalize(key_name)
    #print(to_str(key_name))
    private_key, public_key, der_key = kc.tpm.get_pulic_private_keys(key_name, key_type)
    
    if key_type == 'sm2' or key_type == 'ec':
        para_len = 64
        s = int(private_key, 16)                        
        px = int(public_key[0:para_len], 16)
        py = int(public_key[para_len:2 * para_len], 16)
        SEC1_public_key = (b'\x04' + long_to_bytes(px, para_len >> 1) + long_to_bytes(py, para_len >> 1))
        unrestricted_oid = "1.2.840.10045.2.1"
        ObjectId = "1.2.840.10045.3.1.7"
        if key_type == 'sm2':
            ObjectId = "1.2.156.10197.1.301"

        seq = [1, DerOctetString(long_to_bytes(s, para_len >> 1)), DerObjectId(ObjectId, explicit=0), DerBitString(SEC1_public_key, explicit=1)]  
        del seq[2]
        key_der = DerSequence(seq).encode()
        encrypted_key = PKCS8.wrap(key_der,
                            unrestricted_oid,
                            key_params=DerObjectId(ObjectId),
                            passphrase=passphrase, protection='scryptAndAES256-CBC')            
    else:
        # RSA key
        oid = "1.2.840.113549.1.1.1"
        key = RSA.import_key(der_key)
        binary_key = DerSequence([0,
                                  key.n,
                                  key.e,
                                  key.d,
                                  key.p,
                                  key.q,
                                  key.d % (key.p-1),
                                  key.d % (key.q-1),
                                  Integer(key.q).inverse(key.p)
                                  ]).encode() 
                                         
        encrypted_key = PKCS8.wrap(binary_key, oid, passphrase=passphrase, protection = 'scryptAndAES256-CBC' )
        
    encoded_encrypted_key = encode_encrypted_key(bytes(encrypted_key))                                        
    safbag = make_safebag(bytes(cert.data), encoded_encrypted_key)
    key_b64 = kc.tpm._base64_newline(b64encode(safbag))
    file_name = os.path.expandvars(args.file)
    with open(file_name, 'wb') as f:
        f.write(key_b64)
