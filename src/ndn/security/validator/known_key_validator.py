# modified by liupenghui, added SM2Checker
import abc
from Cryptodome.Hash import SHA256, HMAC
from Cryptodome.PublicKey import ECC, RSA
from Cryptodome.Signature import DSS, pkcs1_15
from ...encoding import FormalName, BinaryStr, NonStrictName, SignaturePtrs, Name, SignatureType
from ...types import Validator
from ...app_support.security_v2 import parse_certificate
from ...security import sm2, sm3, func
from Cryptodome.Math.Numbers import Integer
from Cryptodome.Util.py3compat import bord, tobytes, tostr, bchr, is_string
from Cryptodome.PublicKey import (_expand_subject_public_key_info,
                              _create_subject_public_key_info,
                              _extract_subject_public_key_info)
from Cryptodome.Util.asn1 import (DerObjectId, DerOctetString, DerSequence,
                              DerBitString)
from Cryptodome.Util.number import long_to_bytes, bytes_to_long
                              
def verify_ecdsa(pub_key: ECC.EccKey, sig_ptrs: SignaturePtrs) -> bool:
    verifier = DSS.new(pub_key, 'fips-186-3', 'der')
    h = SHA256.new()
    for content in sig_ptrs.signature_covered_part:
        h.update(content)
    try:
        verifier.verify(h, bytes(sig_ptrs.signature_value_buf))
        return True
    except ValueError:
        return False
        
#added by liupenghui the verifier of sm2 signature.
def verify_sm2(pub_key: str, sig_ptrs: SignaturePtrs) -> bool:

    contentlist = []
    for content in sig_ptrs.signature_covered_part:
        contentlist.extend(func.bytes_to_list(content))
    # fake private key, no need in verification, just for initiation.    
    private_key = "3945208F7B2144B13F36E38AC6D39F95889393692860B51A42FB81EF4DF7C5B8"    
    h = func.list_to_bytes(contentlist)
    sm2_verify = sm2.CryptSM2(public_key=pub_key, private_key=private_key)
    
    # if we use DER format of signature, the following comments can be used.    
    der_seq = DerSequence().decode(bytes(sig_ptrs.signature_value_buf), strict=True)  
    r_prime, s_prime = Integer(der_seq[0]), Integer(der_seq[1])
    
    # if we use binary format of signature.
    #signature = bytes(sig_ptrs.signature_value_buf)
    #r_prime, s_prime = [Integer.from_bytes(x)
    #                    for x in (signature[:32],
    #                              signature[32:])]
    #r_prime, s_prime = [Integer(bytes_to_long(x))
    #                    for x in (signature[:32],
    #                              signature[32:])]    
    
    sig_value ='%064x%064x' % (r_prime, s_prime) 
    #print("\nverify_sm2 message sig_value2:")    
    #print(sig_value)
    h_value ='%s' % h 
    #print("\nverify_sm2 message content2:")
    #print(h_value)
    
    #print("\nverify_sm2 verify_public2")
    #print(pub_key)
    
    #print(sm2_verify.verify_with_sm3(sign=sig_value, data=h))    
    return sm2_verify.verify_with_sm3(sign=sig_value, data=h)

def verify_rsa(pub_key: RSA.RsaKey, sig_ptrs: SignaturePtrs) -> bool:
    verifier = pkcs1_15.new(pub_key)
    h = SHA256.new()
    for content in sig_ptrs.signature_covered_part:
        h.update(content)
    try:
        verifier.verify(h, bytes(sig_ptrs.signature_value_buf))
        return True
    except ValueError:
        return False


def verify_hmac(key: BinaryStr, sig_ptrs: SignaturePtrs) -> bool:
    h = HMAC.new(key, digestmod=SHA256)
    for content in sig_ptrs.signature_covered_part:
        h.update(content)
    try:
        h.verify(sig_ptrs.signature_value_buf)
        return True
    except ValueError:
        return False


class KnownChecker(abc.ABC):
    @classmethod
    @abc.abstractmethod
    def _verify(cls, pub_key_bits, sig_ptrs) -> bool:
        pass

    @classmethod
    def from_key(cls, key_name: NonStrictName, pub_key_bits: BinaryStr) -> Validator:
        key_name = Name.normalize(key_name)

        async def validator(_name: FormalName, sig_ptrs: SignaturePtrs) -> bool:
            if not sig_ptrs.signature_info or not sig_ptrs.signature_info.key_locator:
                return False
            if not sig_ptrs.signature_info.key_locator.name:
                return False
            if not Name.is_prefix(key_name, sig_ptrs.signature_info.key_locator.name):
                return False
            return cls._verify(pub_key_bits, sig_ptrs)

        return validator

    @classmethod
    def from_cert(cls, certificate: BinaryStr) -> Validator:
        cert = parse_certificate(certificate)
        key_name = cert.name[:-2]
        key_bits = cert.content
        return cls.from_key(key_name, key_bits)


class EccChecker(KnownChecker):
    @classmethod
    def _verify(cls, pub_key_bits, sig_ptrs) -> bool:
        if sig_ptrs.signature_info.signature_type != SignatureType.SHA256_WITH_ECDSA:
            return False
        pub_key = ECC.import_key(bytes(pub_key_bits))
        return verify_ecdsa(pub_key, sig_ptrs)

class SM2Checker(KnownChecker):
    @classmethod
    def _verify(cls, pub_key_bits, sig_ptrs) -> bool:
        if sig_ptrs.signature_info.signature_type != SignatureType.SM3_WITH_SM2:
            return False
        #pub_key = ECC.import_key(bytes(pub_key_bits))
        encoded = tobytes(bytes(pub_key_bits))
        oid, ec_point, params = _expand_subject_public_key_info(encoded)
        if not params:
            raise ValueError("Missing SM2 ECC parameters")
        modulus_bytes = 32
        if len(ec_point) != (1 + 2 * modulus_bytes):
            raise ValueError("Incorrect EC point length")
        #x = Integer.from_bytes(ec_point[1:modulus_bytes+1])
        #y = Integer.from_bytes(ec_point[modulus_bytes+1:]) 
        x = Integer(bytes_to_long(ec_point[1:modulus_bytes+1]))
        y = Integer(bytes_to_long(ec_point[modulus_bytes+1:]))          
        para_len = len('FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFF7203DF6B21C6052B53BBF40939D54123')        
        form = '%%0%dx' % para_len
        form = form * 2
        pub_key = form % (x, y)           
        return verify_sm2(pub_key, sig_ptrs)

class RsaChecker(KnownChecker):
    @classmethod
    def _verify(cls, pub_key_bits, sig_ptrs) -> bool:
        if sig_ptrs.signature_info.signature_type != SignatureType.SHA256_WITH_RSA:
            return False
        pub_key = RSA.import_key(bytes(pub_key_bits))
        return verify_rsa(pub_key, sig_ptrs)


class HmacChecker(KnownChecker):
    @classmethod
    def _verify(cls, pub_key_bits, sig_ptrs) -> bool:
        if sig_ptrs.signature_info.signature_type != SignatureType.HMAC_WITH_SHA256:
            return False
        return verify_hmac(pub_key_bits, sig_ptrs)

