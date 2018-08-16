import collections
import random
import hashlib
import hashlib as hasher
import struct
import time
import socket
import datetime as date


EllEquation = collections.namedtuple("EllEquation", 'name p a b g n h')

ligne = EllEquation(
    'secp256k1',
    # Field characteristic.
    p=0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F,
    # Curve coefficients.
    a=0,
    b=7,
    # Base point.
    g=(0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798,
       0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8),
    # Subgroup order.
    n=0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141,
    # Subgroup cofactor.
    h=1
                     )

def extended_euclidian(p, d):

    r = p

    r_by = d

    s_zero = 1

    s_one = 0

    t_zero = 0

    t_one = 1

    while r_by != 0:

        divide = r

        divide_by = r_by

        quotient = divide // divide_by

        r_intermediate = divide - (divide_by * quotient)

        s = s_zero - quotient * s_one

        t = t_zero - quotient * t_one

        s_zero = s_one

        s_one = s

        t_zero = t_one

        t_one = t

        r = divide_by

        r_by = r_intermediate

    return  s_zero% ligne.p

def is_in_ligne(point):
    """Returns True if the given point lies on the elliptic curve."""
    if point is None:
        # None represents the point at infinity.
        return True

    x, y = point

    return (y * y - x * x * x - ligne.a * x - ligne.b) % ligne.p == 0

def point_neg(point):
    """Returns -point."""
    assert is_in_ligne(point)

    if point is None:
        # -0 = 0
        return None

    x, y = point
    result = (x, -y % ligne.p)

    assert is_in_ligne(result)

    return result

def add_points(point1, point2):
    """Returns the result of point1 + point2 according to the group law."""
    assert is_in_ligne(point1)
    assert is_in_ligne(point2)

    if point1 is None:
        # 0 + point2 = point2
        return point2
    if point2 is None:
        # point1 + 0 = point1
        return point1

    xp, yp = point1
    xq, yq = point2

    if xp == xq and yp != yq:
        # point1 + (-point1) = 0
        return None

    if xp == xq:
        # This is the case point1 == point2.
        m = (3 * xp * xp + ligne.a) * extended_euclidian(2 * yp, ligne.p)
    else:
        # This is the case point1 != point2.
        m = (yp - yq) * extended_euclidian(xp - xq, ligne.p)

    xR = m * m - xp - xq
    yR = yp + m * (xR - xp)
    result = (xR  % ligne.p,
              -yR % ligne.p)

    assert is_in_ligne(result)

    return result

def scalar_mult(d, point):
    """Returns d * point computed using the double and point_add algorithm."""
    assert is_in_ligne(point)

    if d % ligne.n == 0 or point is None:
        return None

    if d < 0:
        # d * point = -d * (-point)
        return scalar_mult(-d, point_neg(point))

    result = None
    addend = point

    while d:
        if d & 1:
            # Add.
            result = add_points(result, addend)

        # Double.
        addend = add_points(addend, addend)

        d >>= 1

    assert is_in_ligne(result)

    return result


# Keypair generation and ECDHE ################################################

def make_keypair():
    """Generates a random private-public key pair."""
    private_key = random.randrange(1, ligne.n - 1)
    public_key = scalar_mult(private_key, ligne.g)

    return private_key, public_key

#print('Curve:', ligne.name)

# Alice generates her own keypair.
# I commented this code lines after getting key and considering them fixed
john_private_key, john_public_key = make_keypair()
'''print("John's private key:", hex(john_private_key))
print("John's public key: (0x{:x}, 0x{:x})".format(*john_public_key))'''

john_private_key = 0xb98f7b794fc237a8c4600f8fcfede75738da136eb6a82239f9ab2a0d509aa9b1
john_public_key = 0xbd524d861b025ecb04be8944891be777cb36e399694dd27e1f1a80b0d33afedc, 0xe6ed8bedb05bd664ed91962ae459d7b79837f054cedb1d719305c90fa9f65823
# john address SHA2-256 of his public key

John_address_hash1 = hashlib.sha256(b'0xbd524d861b025ecb04be8944891be777cb36e399694dd27e1f1a80b0d33afedc, 0xe6ed8bedb05bd664ed91962ae459d7b79837f054cedb1d719305c90fa9f65823').hexdigest()
John_address_hash2 = hashlib.sha256(b'eb63cb13c62592a9efaed25bc05c8891f5de54211eac68ace68da07e3a58ae8d').hexdigest()
print("this is John address:"+ John_address_hash2)
John_address = "dd99d3395fcd74d409d7d5e0eca0304b09d4969eea0498083aab2c46a1b4e196"

# bitcoin address
johnpublhash = hashlib.sha256(b'1bd524d861b025ecb04be8944891be777cb36e399694dd27e1f1a80b0d33afedce6ed8bedb05bd664ed91962ae459d7b79837f054cedb1d719305c90fa9f65823').hexdigest()
#print(johnpublhash )
rip = hashlib.new('ripemd160',b'04f771612bb243736446148333845dc379e2d54a689b59b1d4c48407dbf3f8e6').hexdigest()
#print(rip)
checksum1 = hashlib.sha256(b'00cd8275496837e71e39df1ccd6de0073c9a493e60').hexdigest()
#again hash of checksum1
checksum = hashlib.sha256(b'870602766e2e904961e0200e640bc342b0a2865cbf551b125c4f62c7bc5f094c').hexdigest()
#print(checksum)
checksum = 0xd1840d2f1e00ee7eabe9e42cd2ac8447bd8237bc2be1f5a6cc21605d6c3eb7cc
address_checksum = "d1840d2f"
extended_checksum ="00cd8275496837e71e39df1ccd6de0073c9a493e60d1840d2f"

'''john_address = base58.RIPEMD160(SHA256(john_public_key))1ce8db244b17cdd815f87a263e3dc3f512e79e50
print("0x00",john_address)'''

# Bob generates his own key pair.
bob_private_key, bob_public_key = make_keypair()
'''print("Bob's private key:", hex(bob_private_key))
print("Bob's public key: (0x{:x}, 0x{:x})".format(*bob_public_key))'''

bob_private_key = 0x95b696a38dccd9bafca6503b66baa083fe8ddae91a40b8f50c4af238f6f9dda2
bob_public_key = 0x4259198f04cce3094fb10fbed9053d115c3a7d3937d772fbbd9369df00c9de18, 0x1a0d56e746bc6082fea2aa726d324426fb8533c062cfaa9b6b3b6947768a2abb

#BOb address done by sha2-256 of his public key

bob_address_hash1 = hashlib.sha256(b'0x4259198f04cce3094fb10fbed9053d115c3a7d3937d772fbbd9369df00c9de18, 0x1a0d56e746bc6082fea2aa726d324426fb8533c062cfaa9b6b3b6947768a2abb').hexdigest()
bob_address_hash2 = hashlib.sha256(b'49bb592359287148ae985ff8eb5eb089a8bc313ff8ddf508d159e9e31e9603a1').hexdigest()
print("this is bob address:"+ bob_address_hash2)
Bob_address = "1608cd0287106117eddcb4bdd3f4a09e9a3fcc842e665921ce18b374e2c545e9"

#Alice generates her own keypair.
alice_private_key, alice_public_key = make_keypair()
'''print("Alice's private key:", hex(alice_private_key))
print("Alice's public key: (0x{:x}, 0x{:x})".format(*alice_public_key))'''

alice_private_key = 0x8ff8dfc44217ab99a6cf613db3fa69ee14ddca5fb8ecaaa80f9b4d5eaae36b83
alice_public_key = 0x3466951c9c3a177f4dc1dbcecf186ccd092147d75217117561775ee4b32f528a, 0x3f33808a5cd7af1d99f40fd6104161b3b73f97cae45abcd7a31200ea0fb3c8d9
# Alice Address by sha2-256 from her public key

alice_address_sha1 = hashlib.sha256(b'0x3466951c9c3a177f4dc1dbcecf186ccd092147d75217117561775ee4b32f528a, 0x3f33808a5cd7af1d99f40fd6104161b3b73f97cae45abcd7a31200ea0fb3c8d9').hexdigest()
alice_address_sha2 =hashlib.sha256(b'80d1cb706bd450c4dde815dc93b0a1c4dcb7cd1ee72ce1d6d7fdac629657df5c').hexdigest()
print("this is ALICE address:"+ alice_address_sha2)

Alice_address = "ad106cc35a65ef9f62c9c7f6e608180ba11f345b06f29203947bbaf7409957b6"

# Tom generates his own key pair. and after getting them, I keep it fix by commenting the code lines

tom_private_key, tom_public_key = make_keypair()
'''print("Tom's private key:", hex(tom_private_key))
print("Tom's public key: (0x{:x}, 0x{:x})".format(*tom_public_key))'''

tom_private_key = 0x5b43e6165a6eb9f4a58bfc4e88bb1ca25dfd61f3d172af49eba07a83ea254bd0
tom_public_key = 0x86ffd5a37e37048e2e79576dd2b49871b808cd8718a2a2ab7e4fe1c5705ffd30, 0x277708db1441a7b912e5bd9f6b884488cf7613009e3747fd27edea6b7faf634

#TOM address by sha2-256 of his public key

tom_address_sha1 = hashlib.sha256(b'0x86ffd5a37e37048e2e79576dd2b49871b808cd8718a2a2ab7e4fe1c5705ffd30, 0x277708db1441a7b912e5bd9f6b884488cf7613009e3747fd27edea6b7faf634').hexdigest()
Tom_address = hashlib.sha256(b'1c18e801de0b1a252e4da4a309bb2961a2d1285cb164deea29101d56a7a5a55a').hexdigest()
print("this is TOM address:"+ Tom_address)
TOM_Address = "a74678041687f4971d6309000ea71fb46597739e3c72c8d7f9cd2b5bcbd1656f"

#Peter generates her own keypair.
peter_private_key, peter_public_key = make_keypair()
'''print("Peter's private key:", hex(peter_private_key))
print("Peter's public key: (0x{:x}, 0x{:x})".format(*peter_public_key))'''

peter_private_key = 0xa2c922a492ff2128e3a7b48a0623fa0b0f98cff222834c60f98c59f82bfe3d57
peter_public_key = 0x29b794f10ef6bb58c69843c29c596b5cd39f8721817aa996435f4971d027433b, 0x5c472b47f9394d751c3699a82cf4a2a63a08dd5899d41dd4abeaf572c243ed3
#peter address by sha2-256 from his public key
peter_address_sha1 = hashlib.sha256(b'0x29b794f10ef6bb58c69843c29c596b5cd39f8721817aa996435f4971d027433b, 0x5c472b47f9394d751c3699a82cf4a2a63a08dd5899d41dd4abeaf572c243ed3').hexdigest()
peter_address = hashlib.sha256(b'a54c1f5f51ee8f0ecfef0cf3af77da1e0e3a284ea70b35c5b122b82a1cea63fd').hexdigest()
print('this is Peter adress:'+peter_address)
PETER_address = 'a5d8efdffe27103d8fe65e23b29f86379c778b25399b64babbbfa993c9db6cc5'

shared_secret = 0xd063a08021f44cf0ced8a1b495901347f511b9ff74b1efc1aad585c20bc56ff0, 0x69f85da775380b5ab4a1e4faa12a0154e28ede1914e73300032f5153b465e0c4



########transactions

#creation of block


'''class Block:
def__init__(self, index, previousHash, timestamp, date, currentHash):

    self.index = index
    self.previousHash = previousHash
    self.timestamp = timestamp
    self.date = date
    self.currentHash = currentHash'''

  

#Signing a message
#for first trans = message

def hash_message(message):
    """Returns the truncated SHA521 hash of the message."""
    message_hash = hashlib.sha512(message).digest()
    #message_hash = hashlib.sha256(message_hash_0).digest()
    e = int.from_bytes(message_hash, 'big')

    # FIPS 180 says that when a hash needs to be truncated, the rightmost bits
    # should be discarded.
    z = e >> (e.bit_length() - ligne.n.bit_length())

    assert z.bit_length() <= ligne.n.bit_length()

    return z


def sign_message(private_key, message):
    z = message_hash(message)
    r = 0
    s = 0

    while not r or not s:
        k = random.randrange(1, ligne.n)
        x, y = scalar_mult(k, ligne.g)

        r = x % ligne.n
        s = ((z + r * private_key) * extended_euclidian(k, ligne.n)) % ligne.n
       
        return (r, s)
    
def verify_signature(public_key, message, signature):
    z = message

    r, s = signature

    w = extended_euclidian(s, ligne.n)
    u1 = (z * w) % ligne.n
    u2 = (r * w) % ligne.n

    x, y = add_points(scalar_mult(u1, ligne.g),
                     scalar_mult(u2, public_key))

    if (r % ligne.n) == (x % ligne.n):
        return 'signature matches'
    else:
        return 'invalid signature'

'''def create_genesis_block():
  # Manually construct a block with
  # index zero and arbitrary previous hash
return Block(0, date.datetime.now(), "Genesis Block", "0")'''
#genesis block creation

def GenesisBlock(self):
    self.previousBlock = '0'
    self.merkleroot = '0x00'
    self.nonce = "Q",random.getrandbits(64)
    self.difficulty_target = 2^32
    return GenesisBlock(previousBlock, merkleroot, nonce, difficulty_target)

class Block:
  def __init__(self, index, timestamp, message, previous_hash):
    self.index = index
    self.timestamp = timestamp
    self.message = message1
    self.previous_hash = (0xf2bcb41a2f00fee7acebd26c81324a8ec55700e49b4deb584132fb583a52b8be, 0x4742c241fd2cf5f665ebf840f8857cde5cc1f53585e6cd46ad42a161b1442706)
    self.hash = self.hash_block()

  def hash_block(self):
    sha = hasher.sha256()
    sha.update(str(self.index) + 
               str(self.timestamp) + 
               str(self.data) + 
               str(self.previous_hash))
    return sha.hexdigest()


print('Curve:', ligne.name)

private, public = make_keypair()
private1 = 0xb98f7b794fc237a8c4600f8fcfede75738da136eb6a82239f9ab2a0d509aa9b1
public1 = (0xbd524d861b025ecb04be8944891be777cb36e399694dd27e1f1a80b0d33afedc, 0xe6ed8bedb05bd664ed91962ae459d7b79837f054cedb1d719305c90fa9f65823)
print("Private key:", hex(private))
print("Public key: (0x{:x}, 0x{:x})".format(*public))

message1 = b'0xbd524d861b025ecb04be8944891be777cb36e399694dd27e1f1a80b0d33afedc, 0xe6ed8bedb05bd664ed91962ae459d7b79837f054cedb1d719305c90fa9f65823) to (0x86ffd5a37e37048e2e79576dd2b49871b808cd8718a2a2ab7e4fe1c5705ffd30, 0x277708db1441a7b912e5bd9f6b884488cf7613009e3747fd27edea6b7faf634) 30 coins'

signature = sign_message(private1, message1)

print()
print('Message:', message1)
print('Signature: (0x{:x}, 0x{:x})'.format(*signature))
print('Verification:', verify_signature(public1, message1, signature))






# Transactions

# hash of transction1

tx1hash1 = hashlib.sha256(b'((0xbd524d861b025ecb04be8944891be777cb36e399694dd27e1f1a80b0d33afedc, 0xe6ed8bedb05bd664ed91962ae459d7b79837f054cedb1d719305c90fa9f65823) to (0x86ffd5a37e37048e2e79576dd2b49871b808cd8718a2a2ab7e4fe1c5705ffd30, 0x277708db1441a7b912e5bd9f6b884488cf7613009e3747fd27edea6b7faf634) 30 coins').hexdigest()
tx1_hash =hashlib.sha256(b'53f6ceaa340315c7c94de3ae76d73f5cfb8e510101e791479ad500d5fcdf098e').hexdigest()
#print("this txisha1:" +tx1hash1 )
print("this TX1_HASH:"+ tx1_hash)


#hash of transaction2
tx2hash1 = hashlib.sha256(b'(0x86ffd5a37e37048e2e79576dd2b49871b808cd8718a2a2ab7e4fe1c5705ffd30, 0x277708db1441a7b912e5bd9f6b884488cf7613009e3747fd27edea6b7faf634) to (0x3466951c9c3a177f4dc1dbcecf186ccd092147d75217117561775ee4b32f528a, 0x3f33808a5cd7af1d99f40fd6104161b3b73f97cae45abcd7a31200ea0fb3c8d9) 60 coins').hexdigest()
tx2_hash =hashlib.sha256(b'e9cb62134bd14fefa1af9b2e5f71d945322d06f660561b305a5c76afc9e85083').hexdigest()
#print("this tx2sha1:" +tx2hash1)
print("this TX2_HASH:"+ tx2_hash)


#hash of transaction3
tx3hash1 = hashlib.sha256(b'(0x4259198f04cce3094fb10fbed9053d115c3a7d3937d772fbbd9369df00c9de18, 0x1a0d56e746bc6082fea2aa726d324426fb8533c062cfaa9b6b3b6947768a2abb) to (0xbd524d861b025ecb04be8944891be777cb36e399694dd27e1f1a80b0d33afedc, 0xe6ed8bedb05bd664ed91962ae459d7b79837f054cedb1d719305c90fa9f65823) 40 coins').hexdigest()
tx3_hash =hashlib.sha256(b'b9779d4861bed30d96a373b6f926c83f23c91f03730ebe25d75c025323938b02').hexdigest()
#print("tx3sha1:"+tx3hash1)
print("this TX3_HASH:"+ tx3_hash)

#hash of transaction 4

tx4hash1 = hashlib.sha256(b'(0x3466951c9c3a177f4dc1dbcecf186ccd092147d75217117561775ee4b32f528a, 0x3f33808a5cd7af1d99f40fd6104161b3b73f97cae45abcd7a31200ea0fb3c8d9) to (0xbd524d861b025ecb04be8944891be777cb36e399694dd27e1f1a80b0d33afedc, 0xe6ed8bedb05bd664ed91962ae459d7b79837f054cedb1d719305c90fa9f65823) 30 coins').hexdigest()
tx4_hash =hashlib.sha256(b'75b5080cc4e6c09bfb592aee1321c94b93e3a92b71062e0e5cd3d6e20a375bd6').hexdigest()
#print("tx4sha1:"+tx4hash1)
print("this TX4_HASH:"+ tx4_hash)

#hash of transaction5
tx5hash1 = hashlib.sha256(b'(0x29b794f10ef6bb58c69843c29c596b5cd39f8721817aa996435f4971d027433bb, 0x5c472b47f9394d751c3699a82cf4a2a63a08dd5899d41dd4abeaf572c243ed3) to (0x4259198f04cce3094fb10fbed9053d115c3a7d3937d772fbbd9369df00c9de18, 0x1a0d56e746bc6082fea2aa726d324426fb8533c062cfaa9b6b3b6947768a2abb) 50 coins').hexdigest()
tx5_hash =hashlib.sha256(b'1b3353332ad01d17fc699714601b0d6f92b4f6208bab7f3e2bd79d43e5579159').hexdigest()
#print("tx5sha1:"+tx5hash1)
print("this TX5_HASH:"+ tx5_hash)

            
#hash of transaction 6
tx6hash1 = hashlib.sha256(b'(0x29b794f10ef6bb58c69843c29c596b5cd39f8721817aa996435f4971d027433bb, 0x5c472b47f9394d751c3699a82cf4a2a63a08dd5899d41dd4abeaf572c243ed3) to (0xbd524d861b025ecb04be8944891be777cb36e399694dd27e1f1a80b0d33afedc, 0xe6ed8bedb05bd664ed91962ae459d7b79837f054cedb1d719305c90fa9f65823) 30 coins').hexdigest()
tx6_hash =hashlib.sha256(b'96b1090e8189d98974693ecc9a40908e7213396f1a76a581086ada714192a3e1').hexdigest()
#print("tx6sha1:"+tx6hash1)
print("this TX6_HASH:"+ tx6_hash)

#hash of transaction 7
tx7hash1 = hashlib.sha256(b'(0x3466951c9c3a177f4dc1dbcecf186ccd092147d75217117561775ee4b32f528a, 0x3f33808a5cd7af1d99f40fd6104161b3b73f97cae45abcd7a31200ea0fb3c8d9) to (0x29b794f10ef6bb58c69843c29c596b5cd39f8721817aa996435f4971d027433bb, 0x5c472b47f9394d751c3699a82cf4a2a63a08dd5899d41dd4abeaf572c243ed3) 40 coins').hexdigest()
tx7_hash =hashlib.sha256(b'55d86cad20fb50170c04c99dc54a9d96b68d8875896ab515eb3baf3c1de0bc4d').hexdigest()
#print("tx7sha1:"+tx7hash1)
print("this TX7_HASH:"+ tx7_hash)

#hash of transaction8

tx8hash1 = hashlib.sha256(b'(0x4259198f04cce3094fb10fbed9053d115c3a7d3937d772fbbd9369df00c9de18, 0x1a0d56e746bc6082fea2aa726d324426fb8533c062cfaa9b6b3b6947768a2abb) to (0x3466951c9c3a177f4dc1dbcecf186ccd092147d75217117561775ee4b32f528a, 0x3f33808a5cd7af1d99f40fd6104161b3b73f97cae45abcd7a31200ea0fb3c8d9) 20 coins').hexdigest()
tx8_hash =hashlib.sha256(b'328f1539313444f8958c1baefe2cb2036ab920e5baba316872123a3104e493d5').hexdigest()
#print("tx8sha1:"+tx8hash1)
print("this TX8_HASH:"+ tx8_hash)
tx8hash = "97d103baddf2c89aee221969271d9b463caa05a049e5956c23168ad0f498507b"

# hash of transaction 9
tx9hash1 = hashlib.sha256(b'(0xbd524d861b025ecb04be8944891be777cb36e399694dd27e1f1a80b0d33afedc, 0xe6ed8bedb05bd664ed91962ae459d7b79837f054cedb1d719305c90fa9f65823) to (0x86ffd5a37e37048e2e79576dd2b49871b808cd8718a2a2ab7e4fe1c5705ffd30, 0x277708db1441a7b912e5bd9f6b884488cf7613009e3747fd27edea6b7faf634) 10 coins').hexdigest()
tx9_hash =hashlib.sha256(b'749ac83e015b516aad05617a798222ca00a857129f7fe896bed92a3693b07db3').hexdigest()
#print("tx9sha1:"+tx9hash1)
print("this TX9_HASH:"+ tx9_hash)


#hash of trancsaction 10
tx10hash1 = hashlib.sha256(b'(0x3466951c9c3a177f4dc1dbcecf186ccd092147d75217117561775ee4b32f528a, 0x3f33808a5cd7af1d99f40fd6104161b3b73f97cae45abcd7a31200ea0fb3c8d9) to (0x4259198f04cce3094fb10fbed9053d115c3a7d3937d772fbbd9369df00c9de18, 0x1a0d56e746bc6082fea2aa726d324426fb8533c062cfaa9b6b3b6947768a2abb) 20 coins').hexdigest()
tx10_hash =hashlib.sha256(b'9e0fafe14e5283e4018efd690025482070908d6fde455344f15246ea5c076bc5').hexdigest()
#print("tx10sha1:"+tx10hash1)
print("this TX10_HASH:"+ tx10_hash)

'''def makelist_tx():


PreviousBlock= struct.pack()
    Merkle_root = struct.pack()
    Nonce = struct.pack("Q", random.getrandbits(64))
    Timestamp = struct.pack("4", time.time())
    Difficulty_target = struct.pack()

    return GenesisBlock(0, '0', '')'''


#hashing function for message

'''def encrypt_hash2(message):
    """Returns the truncated SHA2(256) hash of the message."""
    encrypt_hash2 = hashlib.sha256(hashlib.sha256(message).hexdigest()).hexdigest()
    e = int.from_bytes(encrypt_hash2, 'big')

    # FIPS 180 says that when a hash needs to be truncated, the rightmost bits
    # should be discarded.
    m = e >> (e.bit_length() - ligne.n.bit_length())

    assert m.bit_length() <= ligne.n.bit_length()

    return m'''











'''def signing_msg(bob_private_key, tx1hash):
    m = 'ada95d11773a712ff895693a2ceef46421d646b7163afb3f0c0f7a2c46647fc8' #encrypt_hash2(message)

    r = 0
    s = 0

    while not r or not s:
        d = random.randrange(1, ligne.n-1)
        x, y = scalar_mult(d, ligne.g)

        r = x % ligne.n
        s = ((m + r * private_key) * extended_euclidian(d, ligne.n)) % ligne.n

    return (r, s)'''

s1 = scalar_mult(john_private_key, m)
print('signature on 1st message'+s1)

print('Shared secret: (0x{:x}, 0x{:x})'.format(*s1))
#pub of bob_public_key to verfy

def verify_signature(public_key, message, signature):
    m = message # hashed transaction replacing message as named

    r, s = signature

    w = extended_euclidian(s, ligne.n)
    u1 = (m * w) % ligne.n
    u2 = (r * w) % ligne.n

    x, y = add_points(scalar_mult(u1, ligne.g),
                     scalar_mult(u2, public_key))

    if (r % ligne.n) == (x % ligne.n):
        return 'valid signature'
    else:
        return 'invalid signature'

#


version = struct.pack("L", 70002)
services = struct.pack("Q", 0)
timestamp = struct.pack("Q", time.time())
addr_recv_services = struct.pack("Q", 0)
addr_recv_IPaddress = struct.pack(">16s","127.0.0.1")
addr_recv_port = struct.pack(">H", 8333)
addr_tr_services = struct.pack("Q", 0)
addr_tr_IPaddress = struct.pack(">16s","127.0.0.1")
addr_tr_port = struct.pack(">H", 8333)
nonce = struct.pack("Q", random.getrandbits(64))

#user_agent_bytes =struct.pack("B", 0)
size = struct.pack("L",395292)#to adjust according to network
#relay = struck.pack("?", false)

#version message with all fields to transmit

payload = version + services + timestamp + addr_recv_services + addr_recv_IPaddress +\
          addr_recv_port + addr_tr_services + addr_tr_IPaddress + addr_tr_port + nonce

#message header

magic = "F9BEB4D9".decode("hex")
command = "version" + 5 * "\00"
size = struct.pack("L", len(payload))
checksum = hashlib.sha256(hashlib.sha256(b'+payload').hexdigest()).hexdigest()[:4]

# message title
message = magic + command + size + checksum + payload

#to get connect online
s = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
#remote machine addresses
HOST = "127.0.0.1"
PORT =8333
#To connect to remote device
s.connect((HOST, PORT))
s.send (message)
s.recv(100)



