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
import unittest
from Cryptodome.Hash import SHA224, SHA256, SHA384, SHA512, SHA3_224, SHA3_256, SHA3_384, SHA3_512, BLAKE2b, BLAKE2s, HMAC
from Cryptodome.Util.py3compat import b, tobytes
from ndn.security.sm3 import sm3_HAMC
from ndn.security.hashs import SHA2_224, SHA2_256, SHA2_384, SHA2_512, SHA3__224,SHA3__256, SHA3__384, SHA3__512, SHA_BLAKE2b, SHA_BLAKE2s

class TestSHA2_224(unittest.TestCase):
    def test_data(self):
        h = SHA224.new()
        h.update(tobytes('Frank jagt im komplett verwahrlosten Taxi quer durch Bayern'))
        out = h.hexdigest()
        self.assertEqual('58911e7fccf2971a7d07f93162d8bd13568e71aa8fc86fc1fe9043d1', out)

class TestSHA2_256(unittest.TestCase):
    def test_data(self):
        h = SHA256.new()
        h.update(tobytes('Franz jagt im komplett verwahrlosten Taxi quer durch Bayern'))
        out = h.hexdigest()
        self.assertEqual('d32b568cd1b96d459e7291ebf4b25d007f275c9f13149beeb782fac0716613f8', out)

class TestSHA2_384(unittest.TestCase):
    def test_data(self):
        h = SHA384.new()
        h.update(tobytes('Franz jagt im komplett verwahrlosten Taxi quer durch Bayern'))
        out = h.hexdigest()
        self.assertEqual('71e8383a4cea32d6fd6877495db2ee353542f46fa44bc23100bca48f3366b84e809f0708e81041f427c6d5219a286677', out)

class TestSHA2_512(unittest.TestCase):
    def test_data(self):
        h = SHA512.new()
        h.update(tobytes('Franz jagt im komplett verwahrlosten Taxi quer durch Bayern'))
        out = h.hexdigest()
        self.assertEqual('af9ed2de700433b803240a552b41b5a472a6ef3fe1431a722b2063c75e9f07451f67a28e37d09cde769424c96aea6f8971389db9e1993d6c565c3c71b855723c', out)

class TestSHA3_224(unittest.TestCase):
    def test_data(self):
        msg = b("rrrrttt")
        h = SHA3_224.new(data=msg[:4])
        out = h.digest().hex()
        self.assertEqual('ebd3b542be77683d6536d9a377bc0c42b1aa0902f868c096c7912311', out)

class TestSHA3_256(unittest.TestCase):
    def test_data(self):
        msg = b("rrrrttt")
        h = SHA3_256.new(data=msg[:4])
        out = h.digest().hex()
        self.assertEqual('61416c3316d4233005fefd90c887b8e64053d095a1a31aac52bdc98e702a023e', out)

class TestSHA3_384(unittest.TestCase):
    def test_data(self):
        msg = b("rrrrttt")
        h = SHA3_384.new(data=msg[:4])
        out = h.digest().hex()
        self.assertEqual('7aef3d66d9209a3027d38bbce2fb87a2da6ccb0acf1cdbae604ceee5cd58ef24759d9f7eb45ae3577d54565b015f697e', out)

class TestSHA3_512(unittest.TestCase):
    def test_data(self):
        msg = b("rrrrttt")
        h = SHA3_512.new(data=msg[:4])
        out = h.digest().hex()
        self.assertEqual('cc7ddf63407e70dd9cb76c0574f34a236f715dc12a85e85bd5c40f8ca00c8e7a1ae21ce4a602e513df6a8d864fe097743fc2e2e5c3a482301ead2010390c6bc2', out)

class TestBLAKE2b(unittest.TestCase):
    def test_data(self):
        pieces = [b"\x0A" * 200, b"\x14" * 300]
        h = BLAKE2b.new(digest_bytes=64)
        h.update(pieces[0]).update(pieces[1])
        digest = h.digest()
        self.assertEqual(h.digest().hex(), 'de39756d49c6c5dd87356d7f7f22cf0f0f5efb5df7bfdc59d10285c88f507d07972b61064c2c31b6bb2f79fdb205f9030a31cb9d7d00b1a201312008a2fc6905')
        h = BLAKE2b.new(digest_bytes=64)
        h.update(pieces[0] + pieces[1])
        self.assertEqual(h.digest().hex(), 'de39756d49c6c5dd87356d7f7f22cf0f0f5efb5df7bfdc59d10285c88f507d07972b61064c2c31b6bb2f79fdb205f9030a31cb9d7d00b1a201312008a2fc6905')
        self.assertEqual(h.digest(), digest)

class TestBLAKE2s(unittest.TestCase):
    def test_data(self):
        pieces = [b"\x0A" * 200, b"\x14" * 300]
        h = BLAKE2s.new(digest_bytes=32)
        h.update(pieces[0]).update(pieces[1])
        digest = h.digest()
        self.assertEqual(h.digest().hex(), '2ea0a7440483dd2d33509ee53c119646e1dbaa76bd04d396ef09c23eb8b8d077')
        h = BLAKE2s.new(digest_bytes=32)
        h.update(pieces[0] + pieces[1])
        self.assertEqual(h.digest().hex(), '2ea0a7440483dd2d33509ee53c119646e1dbaa76bd04d396ef09c23eb8b8d077')
        self.assertEqual(h.digest(), digest)        

class TestHMAC(unittest.TestCase):
    def test_data(self):
        key = b"\x90\x91\x92\x93" * 4
        payload = b"\x00" * 100
        hash_modules = dict(SHA256=[SHA256, 'c1cfb115048f70435eca7c29aa2213ee2c4ffe42e5daa299d99de6f662675286'],
                    SHA224=[SHA224,'ffe7e935358e1af44dd8b8d75e35ad86eaf7e80601fdea6046a98f3b'], 
                    SHA384=[SHA384,'3dbbc080feec658d0c8fa83323144d1538ce961d0a9f40d519f70b4f752fc63059771aad149155a611498b868af80339'], 
                    SHA512=[SHA512,'31112304147d65b78415f1293b76647333a30ae04f011bcf37bc81d2f9cd097ebeb246a8fcbbedf93f119445840706cf1414240600318b80cc31eca4fc20753b'],
                    SHA3_224=[SHA3_224,'b14d5f661e559fd9e1e6cc4600f9994d3c40d103166c203d17b3f8dc'], 
                    SHA3_256=[SHA3_256,'d4348613980935cccb776779e14a73852fdd47259d5d9fb45cce1bb12eb0620c'],
                    SHA3_384=[SHA3_384,'ef35cc1411c5c4099998e50f368f5cc3d22fd98853c473f353d3bae05f6e1107f8ab54f0f43130e6d3fed06e1bbef491'], 
                    SHA3_512=[SHA3_512,'7ee0aa49532e86a47e46a5b475484d4173b0e46640b6fc0f6d8c46c0f6d5beec1f2ff281df01b6e97f8b689a1a319c6f7633b928b9eb12fcd8d2c6e7f72bb919'])
        
        #test HMAC with different hash algorithms...            
        for hashname, hashmod in hash_modules.items():
            if hashmod[0] is None:
                continue
            #hashmod[0] store the corresponding hash algorithm module name, hashmod[1] stores the corresponding the hash value for the same payload.
            one = HMAC.new(key, payload, hashmod[0]).digest()
            self.assertEqual(one.hex(), hashmod[1])  
            
            two = HMAC.new(key, payload, hashmod[0].new()).digest()
            self.assertEqual(two.hex(), hashmod[1])  
            self.assertEqual(one, two)   
            
        #for sm3 HMAC, we implement it as below
        ret = sm3_HAMC(key=key, msg=payload)
        self.assertEqual(ret.hex(),'54a5851c2648458c5c08c5a1f8355a79e65721bd9ff42f701c637cd12ce8e65a')
        
        
def main():     
    test1 = TestSHA2_224()
    test1.test_data() 
    print("TestSHA2_224 OK!") 
    
    test1 = TestSHA2_256()
    test1.test_data() 
    print("TestSHA2_256 OK!")  

    test1 = TestSHA2_384()
    test1.test_data() 
    print("TestSHA2_384 OK!")   

    test1 = TestSHA2_512()
    test1.test_data() 
    print("TestSHA2_512 OK!")   

    test1 = TestSHA3_224()
    test1.test_data() 
    print("TestSHA3_224 OK!")   

    test1 = TestSHA3_256()
    test1.test_data() 
    print("TestSHA3_256 OK!") 

    test1 = TestSHA3_384()
    test1.test_data() 
    print("TestSHA3_384 OK!") 

    test1 = TestSHA3_512()
    test1.test_data() 
    print("TestSHA3_512 OK!") 

    test1 = TestBLAKE2b()
    test1.test_data() 
    print("TestBLAKE2b OK!") 

    test1 = TestBLAKE2s()
    test1.test_data() 
    print("TestBLAKE2s OK!") 

    test1 = TestHMAC()
    test1.test_data() 
    print("TestHMAC OK!") 
    
    data = b'111'
    result = SHA2_224(data)
    assert result == '2b88818c9e8511ae74d9add26c7e9d5380a2ae7c2eee4d9ca84d0649'
    print("SHA2_224 OK!") 
    
    result = SHA2_256(data)
    assert result == 'f6e0a1e2ac41945a9aa7ff8a8aaa0cebc12a3bcc981a929ad5cf810a090e11ae'
    print("SHA2_256 OK!") 
   
    result = SHA2_384(data)
    assert result == 'f9a1ff3af647d412447a4bd475cb60c065157d16520cb7c9c4575ea7ae3aad4f654912aeb185b82fb3a032bfa22457c8'
    print("SHA2_384 OK!") 
    
    result = SHA2_512(data)
    assert result == 'fb131bc57a477c8c9d068f1ee5622ac304195a77164ccc2d75d82dfe1a727ba8d674ed87f96143b2b416aacefb555e3045c356faa23e6d21de72b85822e39fdd'
    print("SHA2_512 OK!") 
    
    result = SHA3__224(data)
    assert result == '9b8c0b84c1ed4c649aca41d733cc2dddb706daba449688da33405abe'
    print("SHA3__224 OK!") 
    
    result = SHA3__256(data)
    assert result == '68f1927d51ddd7b49c381c7c7d006b813565e3b95f09136cdfc96f529a352a4e'
    print("SHA3__256 OK!") 
    
    result = SHA3__384(data)
    assert result == '914d8805996d8254a82715cd405dd169d2bef82f9cae428350cb1cda25aaa00c1a90fd70b52df0ee6dde1a3aec12b3e3'
    print("SHA3__384 OK!") 
    
    result = SHA3__512(data)
    assert result == 'df9e15ba741d17903e8163a8d071d1c6c832965777798f4f65634e2e049fb240965f72befd1a130a7a4f219f8d31dbd91aa14ae1f05806a85e5967ae1d30bd6a'
    print("SHA3__512 OK!")
    
    result = SHA_BLAKE2b(data)
    assert result == '0a4e8a6a5277a26be73e0d7044704bd60902222dc858968064b37d15c865c88ab1137dff96db98a24b68c9effbfdbedc3551dc40a4208a1ffd8e6e167cc45be9'
    print("SHA_BLAKE2b OK!") 
    
    result = SHA_BLAKE2s(data)
    assert result == 'b3007f2435583f0b6908db203e0d5feb5270da80ee52b158f86327a98d2d944f'
    print("SHA_BLAKE2s OK!")    
    
if __name__ == '__main__':
    main()
