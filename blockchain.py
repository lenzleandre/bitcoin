import hashlib
import random
import time
import hashlib as hasher
import datetime as date

class Block:
   def __init__(self, index, timestamp, data, previous_hash):
      self.index = index
      self.timestamp = timestamp
      self.data = data
      self.previous_hash = previous_hash
      self.hash = self.hash_block()

   def hash_block(self):
      sha = hasher.sha256()
      line = str(self.index) + str(self.timestamp) + str(self.data) + str(self.previous_hash)
      sha1 = hashlib.sha256(line.encode('utf-8')).hexdigest()
      return sha1

def create_genesis_block():
  # Manually construct a block with
  # index zero and arbitrary previous hash
   return Block(0, date.datetime.now(), "Genesis Block", "0")

'''def __init__(self, index, timestamp, data, previous_hash):
    self.index = index 
    self.timestamp = timestamp
    self.data = data
    self.previous_hash = previous_hash
    self.hash = self.hash_block()

def hash_block(self):
   sha = hasher.sha256()
   sha.update(str(self.index) + str(self.timestamp) + str(self.data) + str(self.previous_hash))
   return sha.hexdigest()'''

genesis_block = {
      'index': create_genesis_block().index,
      'timestamp': create_genesis_block().timestamp,
      'data': create_genesis_block().data,
      'previous_hash': create_genesis_block().previous_hash
      }
genesis_block_str = str(genesis_block['index']) + str(genesis_block['timestamp']) + str(genesis_block['data']) + str(genesis_block['previous_hash'])
genesis_block_hash = hashlib.sha256(genesis_block_str.encode('utf-8')).hexdigest()
#msg1
john = Block(1, date.datetime.now(),"(0xbd524d861b025ecb04be8944891be777cb36e399694dd27e1f1a80b0d33afedc, 0xe6ed8bedb05bd664ed91962ae459d7b79837f054cedb1d719305c90fa9f65823) to (0x86ffd5a37e37048e2e79576dd2b49871b808cd8718a2a2ab7e4fe1c5705ffd30, 0x277708db1441a7b912e5bd9f6b884488cf7613009e3747fd27edea6b7faf634) 30 coins",genesis_block_hash)
john_block = {
      'index': john.index,
      'timestamp': john.timestamp,
      'data': john.data,
      'previous_hash': john.previous_hash
      }
john_block_str = str(john_block['index']) + str(john_block['timestamp']) + str(john_block['data']) + str(john_block['previous_hash'])
john_block_hash = hashlib.sha256(john_block_str.encode('utf-8')).hexdigest()


#msg2
tom = Block(2, date.datetime.now(), "(0x86ffd5a37e37048e2e79576dd2b49871b808cd8718a2a2ab7e4fe1c5705ffd30, 0x277708db1441a7b912e5bd9f6b884488cf7613009e3747fd27edea6b7faf634) to (0x3466951c9c3a177f4dc1dbcecf186ccd092147d75217117561775ee4b32f528a, 0x3f33808a5cd7af1d99f40fd6104161b3b73f97cae45abcd7a31200ea0fb3c8d9) 60 coins", john_block_hash)

tom_block = {
      'index': tom.index,
      'timestamp': tom.timestamp,
      'data': tom.data,
      'previous_hash': tom.previous_hash
      }
tom_block_str = str(tom_block['index']) + str(tom_block['timestamp'])+ str(tom_block['data']) + str(tom_block['previous_hash'])
tom_block_hash = hashlib.sha256(tom_block_str.encode('utf-8')).hexdigest()

#msg3

bob = Block(3, date.datetime.now(), "(0x4259198f04cce3094fb10fbed9053d115c3a7d3937d772fbbd9369df00c9de18, 0x1a0d56e746bc6082fea2aa726d324426fb8533c062cfaa9b6b3b6947768a2abb) to (0xbd524d861b025ecb04be8944891be777cb36e399694dd27e1f1a80b0d33afedc, 0xe6ed8bedb05bd664ed91962ae459d7b79837f054cedb1d719305c90fa9f65823) 40 coins",tom_block_hash)
bob_block = {
      'index': bob.index,
      'timestamp': bob.timestamp,
      'data': bob.data,
      'previous_hash': bob.previous_hash
      }
bob_block_str = str(bob_block['index']) + str(bob_block['timestamp']) + str(bob_block['data']) + str(bob_block['previous_hash'])
bob_block_hash = hashlib.sha256(bob_block_str.encode('utf-8')).hexdigest()

#msg4

alice = Block(4, date.datetime.now(), "0x3466951c9c3a177f4dc1dbcecf186ccd092147d75217117561775ee4b32f528a, 0x3f33808a5cd7af1d99f40fd6104161b3b73f97cae45abcd7a31200ea0fb3c8d9) to (0xbd524d861b025ecb04be8944891be777cb36e399694dd27e1f1a80b0d33afedc, 0xe6ed8bedb05bd664ed91962ae459d7b79837f054cedb1d719305c90fa9f65823) 30 coins", bob_block_hash)
alice_block = {
      'index': alice.index,
      'timestamp': alice.timestamp,
      'data': alice.data,
      'previous_hash': alice.previous_hash
      }
alice_block_str = str(alice_block['index']) + str(alice_block['timestamp']) + str(alice_block['data']) + str(alice_block['previous_hash'])
alice_block_hash = hashlib.sha256(alice_block_str.encode('utf-8')).hexdigest()




#print(john_block)
print(john_block_hash)
#print(tom_block)
#print(tom_block_hash)
print(bob_block_hash)
print(alice_block_str)
print(alice_block_hash)


