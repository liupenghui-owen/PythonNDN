# -----------------------------------------------------------------------------
# Added by liupenghui, based on Gmssl LIB
# -----------------------------------------------------------------------------
import sys
from ndn.security import sm3, func
import binascii
if __name__ == '__main__':
    data1 = "008031323334353637383132333435363738FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFC28E9FA9E9D9F5E344D5A9E4BCF6509A7F39789F515AB8F92DDBCBD414D940E9332C4AE2C1F1981195F9904466A39C9948FE30BBFF2660BE1715A4589334C74C7BC3736A2F4F6779C59BDCEE36B692153D0A9877CC62A474002DF32E52139F0A0815857578E97065EBEC6F65BC01095A5F403A46F051B9478E787CA76B0FCF52D8A978CAEBF454CF1F177FBA12BE4F617A38E659200CF74F40657120DBFAB440B"
    data =  binascii.a2b_hex(data1)   
    print(sm3.sm3_hash(func.bytes_to_list(data)))
    y = sm3.sm3_hash(func.bytes_to_list(b"abc"))   
    assert y == '66c7f0f462eeedd9d1f2d46bdc10e4e24167c4875cf2f7a2297da02b8f4ba8e0'
    print("sm3_hash OK!")


