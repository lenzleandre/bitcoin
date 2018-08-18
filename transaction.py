#creation of block
import time
import struct
import hashlib
import random


# Transactions

# hash of transction1
trans1 = '(0xbd524d861b025ecb04be8944891be777cb36e399694dd27e1f1a80b0d33afedc, 0xe6ed8bedb05bd664ed91962ae459d7b79837f054cedb1d719305c90fa9f65823) to (0x86ffd5a37e37048e2e79576dd2b49871b808cd8718a2a2ab7e4fe1c5705ffd30, 0x277708db1441a7b912e5bd9f6b884488cf7613009e3747fd27edea6b7faf634) 30 coins'

tx1hash1 = hashlib.sha256((trans1).encode('utf-8')).hexdigest()
tx1 = hashlib.sha256((tx1hash1).encode('utf-8')).hexdigest()
#print("this TX1_HASH1:"+ tx1hash1)
#print("this TX1_HASH2:"+ tx1)

#hash of transaction2
trans2 = '(0x86ffd5a37e37048e2e79576dd2b49871b808cd8718a2a2ab7e4fe1c5705ffd30, 0x277708db1441a7b912e5bd9f6b884488cf7613009e3747fd27edea6b7faf634) to (0x3466951c9c3a177f4dc1dbcecf186ccd092147d75217117561775ee4b32f528a, 0x3f33808a5cd7af1d99f40fd6104161b3b73f97cae45abcd7a31200ea0fb3c8d9) 60 coins'
tx2hash1 = hashlib.sha256((trans2).encode('utf-8')).hexdigest()
tx2 = hashlib.sha256((tx2hash1).encode('utf-8')).hexdigest()
#print("this TX1_HASH2:"+ tx2)

#hash of transaction3
trans3 = '(0x4259198f04cce3094fb10fbed9053d115c3a7d3937d772fbbd9369df00c9de18, 0x1a0d56e746bc6082fea2aa726d324426fb8533c062cfaa9b6b3b6947768a2abb) to (0xbd524d861b025ecb04be8944891be777cb36e399694dd27e1f1a80b0d33afedc, 0xe6ed8bedb05bd664ed91962ae459d7b79837f054cedb1d719305c90fa9f65823) 40 coins'
tx3hash1 = hashlib.sha256((trans3).encode('utf-8')).hexdigest()
tx3 = hashlib.sha256((tx3hash1).encode('utf-8')).hexdigest()
#hash of transaction 
trans4 = '(0x3466951c9c3a177f4dc1dbcecf186ccd092147d75217117561775ee4b32f528a, 0x3f33808a5cd7af1d99f40fd6104161b3b73f97cae45abcd7a31200ea0fb3c8d9) to (0xbd524d861b025ecb04be8944891be777cb36e399694dd27e1f1a80b0d33afedc, 0xe6ed8bedb05bd664ed91962ae459d7b79837f054cedb1d719305c90fa9f65823) 30 coins'
tx4hash1 = hashlib.sha256((trans4).encode('utf-8')).hexdigest()
tx4 = hashlib.sha256((tx4hash1).encode('utf-8')).hexdigest()

#hash of transaction5
trans5 = '(0x29b794f10ef6bb58c69843c29c596b5cd39f8721817aa996435f4971d027433bb, 0x5c472b47f9394d751c3699a82cf4a2a63a08dd5899d41dd4abeaf572c243ed3) to (0x4259198f04cce3094fb10fbed9053d115c3a7d3937d772fbbd9369df00c9de18, 0x1a0d56e746bc6082fea2aa726d324426fb8533c062cfaa9b6b3b6947768a2abb) 50 coins'

tx5hash1 = hashlib.sha256((trans5).encode('utf-8')).hexdigest()
tx5 = hashlib.sha256((tx5hash1).encode('utf-8')).hexdigest()
#hash of transaction 6
trans6 = '(0x29b794f10ef6bb58c69843c29c596b5cd39f8721817aa996435f4971d027433bb, 0x5c472b47f9394d751c3699a82cf4a2a63a08dd5899d41dd4abeaf572c243ed3) to (0xbd524d861b025ecb04be8944891be777cb36e399694dd27e1f1a80b0d33afedc, 0xe6ed8bedb05bd664ed91962ae459d7b79837f054cedb1d719305c90fa9f65823) 30 coins'
tx6hash1 = hashlib.sha256((trans6).encode('utf-8')).hexdigest()
tx6 = hashlib.sha256((tx6hash1).encode('utf-8')).hexdigest()
#hash of transaction 7
trans7 ='(0x3466951c9c3a177f4dc1dbcecf186ccd092147d75217117561775ee4b32f528a, 0x3f33808a5cd7af1d99f40fd6104161b3b73f97cae45abcd7a31200ea0fb3c8d9) to (0x29b794f10ef6bb58c69843c29c596b5cd39f8721817aa996435f4971d027433bb, 0x5c472b47f9394d751c3699a82cf4a2a63a08dd5899d41dd4abeaf572c243ed3) 40 coins'
tx7hash1 = hashlib.sha256((trans7).encode('utf-8')).hexdigest()
tx7 = hashlib.sha256((tx7hash1).encode('utf-8')).hexdigest()

#hash of transaction8
trans8 ='(0x4259198f04cce3094fb10fbed9053d115c3a7d3937d772fbbd9369df00c9de18, 0x1a0d56e746bc6082fea2aa726d324426fb8533c062cfaa9b6b3b6947768a2abb) to (0x3466951c9c3a177f4dc1dbcecf186ccd092147d75217117561775ee4b32f528a, 0x3f33808a5cd7af1d99f40fd6104161b3b73f97cae45abcd7a31200ea0fb3c8d9) 20 coins'
tx8hash1 = hashlib.sha256((trans8).encode('utf-8')).hexdigest()
tx8 = hashlib.sha256((tx8hash1).encode('utf-8')).hexdigest()

# hash of transaction 9
trans9 = '(0xbd524d861b025ecb04be8944891be777cb36e399694dd27e1f1a80b0d33afedc, 0xe6ed8bedb05bd664ed91962ae459d7b79837f054cedb1d719305c90fa9f65823) to (0x86ffd5a37e37048e2e79576dd2b49871b808cd8718a2a2ab7e4fe1c5705ffd30, 0x277708db1441a7b912e5bd9f6b884488cf7613009e3747fd27edea6b7faf634) 10 coins'
tx9hash1 = hashlib.sha256((trans9).encode('utf-8')).hexdigest()
tx9 = hashlib.sha256((tx9hash1).encode('utf-8')).hexdigest()

#hash of trancsaction 10
trans10 = '(0x3466951c9c3a177f4dc1dbcecf186ccd092147d75217117561775ee4b32f528a, 0x3f33808a5cd7af1d99f40fd6104161b3b73f97cae45abcd7a31200ea0fb3c8d9) to (0x4259198f04cce3094fb10fbed9053d115c3a7d3937d772fbbd9369df00c9de18, 0x1a0d56e746bc6082fea2aa726d324426fb8533c062cfaa9b6b3b6947768a2abb) 20 coins'
tx10hash1 = hashlib.sha256((trans10).encode('utf-8')).hexdigest()
tx10 = hashlib.sha256((tx10hash1).encode('utf-8')).hexdigest()


# hash of all transactions for merkle root
trans0 = 'Genesis Block'
tx0hash1 = hashlib.sha256((trans0).encode('utf-8')).hexdigest()
tx0 = hashlib.sha256((tx0hash1).encode('utf-8')).hexdigest()


my_txs = [tx0, tx1, tx2, tx3, tx4, tx5, tx6, tx7, tx8, tx9 ,tx10]

hah01 = my_txs [0]+ my_txs[1]
hah23 = my_txs [2] + my_txs [3]
hah45 = my_txs [4] + my_txs [5]
hah67 = my_txs [4] + my_txs [7]
hah89 = my_txs [8] + my_txs [9]
hah10_10 = my_txs [9]+ my_txs [10]

Hhash01 = hashlib.sha256((hah01).encode('utf-8')).hexdigest()
Hhash23 = hashlib.sha256((hah23).encode('utf-8')).hexdigest()
Hhash45 = hashlib.sha256((hah45).encode('utf-8')).hexdigest()
Hhash67 = hashlib.sha256((hah67).encode('utf-8')).hexdigest()
Hhash89 = hashlib.sha256((hah89).encode('utf-8')).hexdigest()
Hhash910 = hashlib.sha256((hah10_10).encode('utf-8')).hexdigest()

# hash 2nd combination
txs_hash = [Hhash01, Hhash23, Hhash45, Hhash67, Hhash89, Hhash910]
hash0_3 = txs_hash[0] + txs_hash[1]
hash4_7 = txs_hash[2] + txs_hash[3]
hash8_10 = txs_hash[4] + txs_hash[5]

H_hash0_3 = hashlib.sha256((hash0_3).encode('utf-8')).hexdigest()
H_hash4_7 = hashlib.sha256((hash4_7).encode('utf-8')).hexdigest()
H_hash8_10 = hashlib.sha256((hash8_10).encode('utf-8')).hexdigest()

#hash 3rd combination
last_hash =[H_hash0_3, H_hash4_7, H_hash8_10]

Hhash0_7 = last_hash [0] + last_hash [1]
Hhash8_10 = last_hash [2] + last_hash [2]

H_hash0_7 = hashlib.sha256((Hhash0_7).encode('utf-8')).hexdigest()
H_hash8_10 = hashlib.sha256((Hhash8_10).encode('utf-8')).hexdigest()

# Merkle root level

Merkle = [H_hash0_7, H_hash8_10]
Merkle0 = Merkle[0] + Merkle[1]
Merkle_root = hashlib.sha256((Merkle0).encode('utf-8')).hexdigest()

print('hash of Merkle_root:' + Merkle_root)



