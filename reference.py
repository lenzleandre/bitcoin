import collections
import hashlib
import random

EllipticCurve = collections.namedtuple('EllipticCurve', 'name p a b g n h')

curve = EllipticCurve(
    'secp256k1',
    # Field characteristic.
    p=0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f,
    # Curve coefficients.
    a=0,
    b=7,
    # Base point.
    g=(0x79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798,
       0x483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8),
    # Subgroup order.
    n=0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141,
    # Subgroup cofactor.
    h=1,
)


# Modular arithmetic ##########################################################

def inverse_mod(k, p):
    """Returns the inverse of k modulo p.
    This function returns the only integer x such that (x * k) % p == 1.
    k must be non-zero and p must be a prime.
    """
    if k == 0:
        raise ZeroDivisionError('division by zero')

    if k < 0:
        # k ** -1 = p - (-k) ** -1  (mod p)
        return p - inverse_mod(-k, p)

    # Extended Euclidean algorithm.
    s, old_s = 0, 1
    t, old_t = 1, 0
    r, old_r = p, k

    while r != 0:
        quotient = old_r // r
        old_r, r = r, old_r - quotient * r
        old_s, s = s, old_s - quotient * s
        old_t, t = t, old_t - quotient * t

    gcd, x, y = old_r, old_s, old_t

    assert gcd == 1
    assert (k * x) % p == 1

    return x % p


# Functions that work on curve points #########################################

def is_on_curve(point):
    """Returns True if the given point lies on the elliptic curve."""
    if point is None:
        # None represents the point at infinity.
        return True

    x, y = point

    return (y * y - x * x * x - curve.a * x - curve.b) % curve.p == 0


def point_neg(point):
    """Returns -point."""
    assert is_on_curve(point)

    if point is None:
        # -0 = 0
        return None

    x, y = point
    result = (x, -y % curve.p)

    assert is_on_curve(result)

    return result


def point_add(point1, point2):
    """Returns the result of point1 + point2 according to the group law."""
    assert is_on_curve(point1)
    assert is_on_curve(point2)

    if point1 is None:
        # 0 + point2 = point2
        return point2
    if point2 is None:
        # point1 + 0 = point1
        return point1

    x1, y1 = point1
    x2, y2 = point2

    if x1 == x2 and y1 != y2:
        # point1 + (-point1) = 0
        return None

    if x1 == x2:
        # This is the case point1 == point2.
        m = (3 * x1 * x1 + curve.a) * inverse_mod(2 * y1, curve.p)
    else:
        # This is the case point1 != point2.
        m = (y1 - y2) * inverse_mod(x1 - x2, curve.p)

    x3 = m * m - x1 - x2
    y3 = y1 + m * (x3 - x1)
    result = (x3 % curve.p,
              -y3 % curve.p)

    assert is_on_curve(result)

    return result


def scalar_mult(k, point):
    """Returns k * point computed using the double and point_add algorithm."""
    assert is_on_curve(point)

    if k % curve.n == 0 or point is None:
        return None

    if k < 0:
        # k * point = -k * (-point)
        return scalar_mult(-k, point_neg(point))

    result = None
    addend = point

    while k:
        if k & 1:
            # Add.
            result = point_add(result, addend)

        # Double.
        addend = point_add(addend, addend)

        k >>= 1

    assert is_on_curve(result)

    return result


# Keypair generation and ECDSA ################################################

def make_keypair():
    """Generates a random private-public key pair."""
    private_key = random.randrange(1, curve.n)
    public_key = scalar_mult(private_key, curve.g)

    return private_key, public_key


def hash_message(message):
    """Returns the truncated SHA512 hash of the message."""
    #message_hash = hashlib.sha512(message).digest()
    #line = str(message)
    #message_hash = hashlib.sha256(line.encode('utf-8')).hexdigest()
    message_hash_0 = hashlib.sha256(message).digest()
    message_hash = hashlib.sha256(message_hash_0).digest()
    
    e = int.from_bytes(message_hash, 'big')

    # FIPS 180 says that when a hash needs to be truncated, the rightmost bits
    # should be discarded.
    z = e >> (e.bit_length() - curve.n.bit_length())

    assert z.bit_length() <= curve.n.bit_length()

    return z


def sign_message(private_key, message):
    z = hash_message(message)

    r = 0
    s = 0

    while not r or not s:
        k = random.randrange(1, curve.n)
        x, y = scalar_mult(k, curve.g)

        r = x % curve.n
        s = ((z + r * private_key) * inverse_mod(k, curve.n)) % curve.n

    return (r, s)


def verify_signature(public_key, message, signature):
    z = hash_message(message)

    r, s = signature

    w = inverse_mod(s, curve.n)
    u1 = (z * w) % curve.n
    u2 = (r * w) % curve.n

    x, y = point_add(scalar_mult(u1, curve.g),
                     scalar_mult(u2, public_key))

    if (r % curve.n) == (x % curve.n):
        return 'signature matches'
    else:
        return 'invalid signature'

'''#genesis block creation

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
    self.message = message
    self.previous_hash = previous_hash
    self.hash = self.hash_block()
    msg = verify_signature(message, signature)

    genesis = Block()

    @index.setter
    def set_index(self, index):
        self.index = index
    
    @timestamp.setter
    def set_timestamp(self, time):
        self.timestamp = time
     
    @message.setter
    def set_message(self, message):
        self.message = message
      
    @previous_hash.setter
    def set_previous_hash(self, signature):
        self.previous_hash = signature

        print('genesis time:'+

        return genesis

def hash_block(self):
    sha = hasher.sha256()
    sha.update(str(self.index) + 
               str(self.timestamp) + 
               str(self.message) + 
               str(self.previous_hash))
    print('genesis time:'+)
    return sha.hexdigest()    

# Create the blockchain and add the genesis block
blockchain = [create_genesis_block()]
previous_block = blockchain[0]

# How many blocks should we add to the chain
# after the genesis block
num_of_blocks_to_add = 10

# Add blocks to the chain
for i in range(0, num_of_blocks_to_add):
  block_to_add = next_block(previous_block)
  blockchain.append(block_to_add)
  previous_block = block_to_add
  # Tell everyone about it!
  print ('Block #{} has been added to the blockchain!'.format(block_to_add.index))
  print('Hash: {}\n'.format(block_to_add.hash))'''



print('Curve:', curve.name)

private, public = make_keypair()

privatej = 0xb98f7b794fc237a8c4600f8fcfede75738da136eb6a82239f9ab2a0d509aa9b1
publicj = (0xbd524d861b025ecb04be8944891be777cb36e399694dd27e1f1a80b0d33afedc, 0xe6ed8bedb05bd664ed91962ae459d7b79837f054cedb1d719305c90fa9f65823)
print("Private key:", hex(private))
print("Public key: (0x{:x}, 0x{:x})".format(*public))

msg1 = b'(0xbd524d861b025ecb04be8944891be777cb36e399694dd27e1f1a80b0d33afedc, 0xe6ed8bedb05bd664ed91962ae459d7b79837f054cedb1d719305c90fa9f65823) to (0x86ffd5a37e37048e2e79576dd2b49871b808cd8718a2a2ab7e4fe1c5705ffd30, 0x277708db1441a7b912e5bd9f6b884488cf7613009e3747fd27edea6b7faf634) 30 coins'
signature = sign_message(privatej, msg1)

print()
print('Message:', msg1)
print('Signature: (0x{:x}, 0x{:x})'.format(*signature))
print('Verification:', verify_signature(publicj, msg1, signature))

privatet = 0x5b43e6165a6eb9f4a58bfc4e88bb1ca25dfd61f3d172af49eba07a83ea254bd0 
public_t = (0x86ffd5a37e37048e2e79576dd2b49871b808cd8718a2a2ab7e4fe1c5705ffd30, 0x277708db1441a7b912e5bd9f6b884488cf7613009e3747fd27edea6b7faf634)

print("Private key:", hex(private))
print("Public key: (0x{:x}, 0x{:x})".format(*public))
msg2 = b'(0x86ffd5a37e37048e2e79576dd2b49871b808cd8718a2a2ab7e4fe1c5705ffd30, 0x277708db1441a7b912e5bd9f6b884488cf7613009e3747fd27edea6b7faf634) to (0x3466951c9c3a177f4dc1dbcecf186ccd092147d75217117561775ee4b32f528a, 0x3f33808a5cd7af1d99f40fd6104161b3b73f97cae45abcd7a31200ea0fb3c8d9) 60 coins'
signature= sign_message(privatet, msg2)

print()
print('Message:', msg2)
print('Signature: (0x{:x}, 0x{:x})'.format(*signature))
print('Verification:', verify_signature(public_t, msg2, signature))


'''privateb = 0x95b696a38dccd9bafca6503b66baa083fe8ddae91a40b8f50c4af238f6f9dda2
public_b = (0x4259198f04cce3094fb10fbed9053d115c3a7d3937d772fbbd9369df00c9de18, 0x1a0d56e746bc6082fea2aa726d324426fb8533c062cfaa9b6b3b6947768a2abb)
print("Private key:", hex(private))
print("Public key: (0x{:x}, 0x{:x})".format(*public))
msg3 = b'(0x4259198f04cce3094fb10fbed9053d115c3a7d3937d772fbbd9369df00c9de18, 0x1a0d56e746bc6082fea2aa726d324426fb8533c062cfaa9b6b3b6947768a2abb) to (0xbd524d861b025ecb04be8944891be777cb36e399694dd27e1f1a80b0d33afedc, 0xe6ed8bedb05bd664ed91962ae459d7b79837f054cedb1d719305c90fa9f65823) 40 coins'
signature= sign_message(privateb, msg3)
print()
print('Message:', msg3)
print('Signature3: (0x{:x}, 0x{:x})'.format(*signature))
print('Verification:', verify_signature(public_b, msg3, signature

msg = b'Hi there!'
print()
print('Message:', msg)
print('Verification:', verify_signature(public, msg, signature))

private, public = make_keypair()

msg = b'Hello!'
print()
print('Message:', msg)
print("Public key: (0x{:x}, 0x{:x})".format(*public))
print('Verification:', verify_signature(public, msg, signature))'''
