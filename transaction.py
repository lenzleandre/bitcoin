#creation of block
import time
import struct
import hashlib
import random


'''class Block:
def__init__(self, index, previousHash, timestamp, date, currentHash):

    self.index = index
    self.previousHash = previousHash
    self.timestamp = timestamp
    self.date = date
    self.currentHash = currentHash'''

    # genesis creation
#genesis block header

'''def GenesisBlock(self):
    self.previousBlock = '0'
    self.merkleroot = '0x00'
    self.nonce = "Q",random.getrandbits(64)
    self.difficulty_target = 2^32
    return GenesisBlock(previousBlock, merkleroot, nonce, difficulty_target)'''

# Transactions

# hash of transction1

tx1hash1 = hashlib.sha256(b'((0xbd524d861b025ecb04be8944891be777cb36e399694dd27e1f1a80b0d33afedc, 0xe6ed8bedb05bd664ed91962ae459d7b79837f054cedb1d719305c90fa9f65823) to (0x86ffd5a37e37048e2e79576dd2b49871b808cd8718a2a2ab7e4fe1c5705ffd30, 0x277708db1441a7b912e5bd9f6b884488cf7613009e3747fd27edea6b7faf634) 30 coins').hexdigest()
tx1_hash =hashlib.sha256(b'53f6ceaa340315c7c94de3ae76d73f5cfb8e510101e791479ad500d5fcdf098e').hexdigest()
#print("this txisha1:" +tx1hash1 )
print("this TX1_HASH:"+ tx1_hash)

tx1hash = "ada95d11773a712ff895693a2ceef46421d646b7163afb3f0c0f7a2c46647fc8"
#hash of transaction2
tx2hash1 = hashlib.sha256(b'(0x86ffd5a37e37048e2e79576dd2b49871b808cd8718a2a2ab7e4fe1c5705ffd30, 0x277708db1441a7b912e5bd9f6b884488cf7613009e3747fd27edea6b7faf634) to (0x3466951c9c3a177f4dc1dbcecf186ccd092147d75217117561775ee4b32f528a, 0x3f33808a5cd7af1d99f40fd6104161b3b73f97cae45abcd7a31200ea0fb3c8d9) 60 coins').hexdigest()
tx2_hash =hashlib.sha256(b'e9cb62134bd14fefa1af9b2e5f71d945322d06f660561b305a5c76afc9e85083').hexdigest()
#print("this tx2sha1:" +tx2hash1)
print("this TX2_HASH:"+ tx2_hash)
tx2hash = "48167ecd773192fe6d9dc2e42744a31f5172298d8b2a48fc72bfcd3ec29c7f3d"

#hash of transaction3
tx3hash1 = hashlib.sha256(b'(0x4259198f04cce3094fb10fbed9053d115c3a7d3937d772fbbd9369df00c9de18, 0x1a0d56e746bc6082fea2aa726d324426fb8533c062cfaa9b6b3b6947768a2abb) to (0xbd524d861b025ecb04be8944891be777cb36e399694dd27e1f1a80b0d33afedc, 0xe6ed8bedb05bd664ed91962ae459d7b79837f054cedb1d719305c90fa9f65823) 40 coins').hexdigest()
tx3_hash =hashlib.sha256(b'b9779d4861bed30d96a373b6f926c83f23c91f03730ebe25d75c025323938b02').hexdigest()
#print("tx3sha1:"+tx3hash1)
#print("this TX3_HASH:"+ tx3_hash)
tx3hash = "27632d293ba0ba2737bc41941aa2d5c9c14ea92a960455af4c400b55e8bf1ff5"
#hash of transaction 4

tx4hash1 = hashlib.sha256(b'(0x3466951c9c3a177f4dc1dbcecf186ccd092147d75217117561775ee4b32f528a, 0x3f33808a5cd7af1d99f40fd6104161b3b73f97cae45abcd7a31200ea0fb3c8d9) to (0xbd524d861b025ecb04be8944891be777cb36e399694dd27e1f1a80b0d33afedc, 0xe6ed8bedb05bd664ed91962ae459d7b79837f054cedb1d719305c90fa9f65823) 30 coins').hexdigest()
tx4_hash =hashlib.sha256(b'75b5080cc4e6c09bfb592aee1321c94b93e3a92b71062e0e5cd3d6e20a375bd6').hexdigest()
#print("tx4sha1:"+tx4hash1)
print("this TX4_HASH:"+ tx4_hash)
tx4hash = "93eab63869e78bd604e1d87a1fbefe89d614a879dc0b8d0b32372edc7ab19d5a"
#hash of transaction5
tx5hash1 = hashlib.sha256(b'(0x29b794f10ef6bb58c69843c29c596b5cd39f8721817aa996435f4971d027433bb, 0x5c472b47f9394d751c3699a82cf4a2a63a08dd5899d41dd4abeaf572c243ed3)(0x4259198f04cce3094fb10fbed9053d115c3a7d3937d772fbbd9369df00c9de18, 0x1a0d56e746bc6082fea2aa726d324426fb8533c062cfaa9b6b3b6947768a2abb)(0x29b794f10ef6bb58c69843c29c596b5cd39f8721817aa996435f4971d027433bb, 0x5c472b47f9394d751c3699a82cf4a2a63a08dd5899d41dd4abeaf572c243ed3) to (0x4259198f04cce3094fb10fbed9053d115c3a7d3937d772fbbd9369df00c9de18, 0x1a0d56e746bc6082fea2aa726d324426fb8533c062cfaa9b6b3b6947768a2abb) 50 coins').hexdigest()
tx5_hash =hashlib.sha256(b'1b3353332ad01d17fc699714601b0d6f92b4f6208bab7f3e2bd79d43e5579159').hexdigest()
#print("tx5sha1:"+tx5hash1)
print("this TX5_HASH:"+ tx5_hash)
tx5hash = "4e0c960b9b7d0c99ba2687f9bfc4cc4db14647b09fa575d21f9cbb6e6b16e89b"
#hash of transaction 6
tx6hash1 = hashlib.sha256(b'(0x29b794f10ef6bb58c69843c29c596b5cd39f8721817aa996435f4971d027433bb, 0x5c472b47f9394d751c3699a82cf4a2a63a08dd5899d41dd4abeaf572c243ed3) to (0xbd524d861b025ecb04be8944891be777cb36e399694dd27e1f1a80b0d33afedc, 0xe6ed8bedb05bd664ed91962ae459d7b79837f054cedb1d719305c90fa9f65823) 30 coins').hexdigest()
tx6_hash =hashlib.sha256(b'96b1090e8189d98974693ecc9a40908e7213396f1a76a581086ada714192a3e1').hexdigest()
#print("tx6sha1:"+tx6hash1)
print("this TX6_HASH:"+ tx6_hash)
tx6hash ="aa9a9d6f1adab4b23eba01dcf5974cf392de2f74a43d0009ca6f013eac33d6a8"

#hash of transaction 7
tx7hash1 = hashlib.sha256(b'(0x3466951c9c3a177f4dc1dbcecf186ccd092147d75217117561775ee4b32f528a, 0x3f33808a5cd7af1d99f40fd6104161b3b73f97cae45abcd7a31200ea0fb3c8d9) to (0x29b794f10ef6bb58c69843c29c596b5cd39f8721817aa996435f4971d027433bb, 0x5c472b47f9394d751c3699a82cf4a2a63a08dd5899d41dd4abeaf572c243ed3) 40 coins').hexdigest()
tx7_hash =hashlib.sha256(b'55d86cad20fb50170c04c99dc54a9d96b68d8875896ab515eb3baf3c1de0bc4d').hexdigest()
#print("tx7sha1:"+tx7hash1)
print("this TX7_HASH:"+ tx7_hash)
tx7hash = "e60d44170accf4d9bd0758094c23eea8edee1127fe337a4aae2950194b7253fe"
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
tx9hash = "ecd4f43e9ccd777692fe7f299b0e66efd289e8917c4e42199d4263f63c11cee7"

#hash of trancsaction 10
tx10hash1 = hashlib.sha256(b'(0x3466951c9c3a177f4dc1dbcecf186ccd092147d75217117561775ee4b32f528a, 0x3f33808a5cd7af1d99f40fd6104161b3b73f97cae45abcd7a31200ea0fb3c8d9) to (0x4259198f04cce3094fb10fbed9053d115c3a7d3937d772fbbd9369df00c9de18, 0x1a0d56e746bc6082fea2aa726d324426fb8533c062cfaa9b6b3b6947768a2abb) 20 coins').hexdigest()
tx10_hash =hashlib.sha256(b'9e0fafe14e5283e4018efd690025482070908d6fde455344f15246ea5c076bc5').hexdigest()
#print("tx10sha1:"+tx10hash1)
print("this TX10_HASH:"+ tx10_hash)
tx10hash = "d6dc9898e5988731e04139d640f62e76235955d0b34710ee3e165025bb73523f"


'''def makelist_tx():


PreviousBlock= struct.pack()
    Merkle_root = struct.pack()
    Nonce = struct.pack("Q", random.getrandbits(64))
    Timestamp = struct.pack("4", time.time())
    Difficulty_target = struct.pack()

    return GenesisBlock(0, '0', '')'''
