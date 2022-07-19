# -----------------------------------------------------------------------------
# Added by liupenghui, based on Gmssl LIB
# -----------------------------------------------------------------------------
import sys
import base64
import binascii
from ndn.security import sm2, func


def test_sm2():
    private_key = 'B9AB0B828FF68872F21A837FC303668428DEA11DCD1B24429D0C99E24EED83D5'
    public_key = 'B9C9A6E04E9C91F7BA880429273747D7EF5DDEB0BB2FF6317EB00BEF331A83081A6994B8993F3F5D6EADDDB81872266C87C018FB4162F5AF347B483E24620207'

    sm2_crypt = sm2.CryptSM2(
        public_key=public_key, private_key=private_key)
    data = b"111"
    print("\n-----------------test SM2 encrypt and decrypt--------------")
    enc_data = sm2_crypt.encrypt(data)
    #print("enc_data:%s" % enc_data)
    #print("enc_data_base64:%s" % base64.b64encode(bytes.fromhex(enc_data)))
    dec_data = sm2_crypt.decrypt(enc_data)
    print(b"data:%s" % data)  
    print("enc_data:%s" % enc_data.hex()) # 转化为16进制字符串输出
    print(b"dec_data:%s" % dec_data)
    assert data == dec_data

    print("\n-----------------test SM2 original sign and verify---------------")
    random_hex_str = func.random_hex(sm2_crypt.para_len)
    sign = sm2_crypt.sign(data, random_hex_str)
    print('sign:%s' % sign)
    verify = sm2_crypt.verify(sign, data)
    print('verify:%s' % verify)
    assert verify


def testsm2_with_sm3():
     private_key = "9659367ff1752a377db35c210ebf8697b2bcd3ac1b9de802d351a9d3ed39dcc1"
     public_key = "815857578e97065ebec6f65bc01095a5f403a46f051b9478e787ca76b0fcf52d"\
                  "8a978caebf454cf1f177fba12be4f617a38e659200cf74f40657120dbfab440b"
     random_hex_str = "6166db0dace5bfdde03836394ac7094954b59aabb020df11c37250c6de7e9416"

     sm2_crypt = sm2.CryptSM2(public_key=public_key, private_key=private_key)
     data1 = "07060804746573741403180100150C7465737420636F6E74656E74161F1B01051C1A071808076D79746573743108034B4559080882D23E7E09114EDB"
     data = binascii.a2b_hex(data1) 
     print("\n-----------------test SM2 sign and verify with SM3--------------")
     sign = sm2_crypt.sign_with_sm3(data, random_hex_str)
     print('sign: %s' % sign)
     verify = sm2_crypt.verify_with_sm3(sign, data)
     print('verify: %s' % verify)
     assert verify
     
def main():
    test_sm2()
    print("test_sm2 encrypt and decrypt, original sign and verify OK!")

    testsm2_with_sm3()
    print("test_sm2 sign and verify with SM3 OK!")

if __name__ == '__main__':
    main()

