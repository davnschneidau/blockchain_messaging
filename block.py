import hashlib
import os
import json
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa, utils, padding
from cryptography.exceptions import InvalidSignature
import requests
import json
import utils
from config import *
import binascii

class Block(object):
  def __init__(self, dictionary):
    '''
      We're looking for index, timestamp, data, prev_hash, nonce
    '''
    for key, value in dictionary.items():
      if key in BLOCK_VAR_CONVERSIONS:
        setattr(self, key, BLOCK_VAR_CONVERSIONS[key](value))
      else:
        setattr(self, key, value)
    if not hasattr(self, 'hash'): #in creating the first block, needs to be removed in future
      self.hash = self.update_self_hash()

    if not hasattr(self, 'nonce'):
      #we're throwin this in for generation
      self.nonce = 'None'
    if not hasattr(self, 'hash'): #in creating the first block, needs to be removed in future
      self.hash = self.update_self_hash()

  def header_string(self):
    return str(self.index) + self.prev_hash + self.data + str(self.timestamp) + str(self.nonce)

  def generate_header(index, prev_hash, data, timestamp, nonce):
    return str(index) + prev_hash + data + str(timestamp) + str(nonce)

  def update_self_hash(self):
    sha = hashlib.sha256()
    sha.update(self.header_string().encode('utf-8'))
    new_hash = sha.hexdigest()
    self.hash = new_hash
    return new_hash

  def self_save(self):
    index_string = str(self.index).zfill(6) #front of zeros so they stay in numerical order
    filename = '%s%s.json' % (CHAINDATA_DIR, index_string)
    with open(filename, 'w') as block_file:
      json.dump(self.to_dict(), block_file)

  def add_encrypted_message(self, sender_address, recipient_address, content, signature):
    # Implement a function to add an encrypted message to the block
    self.encrypted_messages.append({
        "sender_address": sender_address,
        "recipient_address": recipient_address,
        "content": content,
        "signature": signature
    })

  def validate_encrypted_messages(self, public_keys):
    # Implement a method to validate encrypted messages using public keys
    for message in self.encrypted_messages:
        sender_key = public_keys.get(message['sender_address'])
        if not sender_key:
            return False
        signature = binascii.unhexlify(message['signature'])
        content = message['content'].encode('utf-8')
        try:
            sender_key.verify(
                signature,
                content,
                padding.PKCS1v15(),
                hashes.SHA256()
            )
        except InvalidSignature:
            return False
    return True

  def to_dict(self):
    # Update to include encrypted messages
    block_dict = {
        "index": self.index,
        "timestamp": self.timestamp,
        "data": self.data,
        "hash": self.hash,
        "previous_hash": self.previous_hash,
        "nonce": self.nonce,
        "encrypted_messages": self.encrypted_messages
    }
    return block_dict

  def is_valid(self):
    self.update_self_hash()
    NUM_ZEROS = self.hash.count('0')
    print(str(self.hash))
    print(str(self.hash[0:NUM_ZEROS]))
    print('0' * NUM_ZEROS)

    if str(self.hash[0:NUM_ZEROS]) == '0' * NUM_ZEROS:
      return True
    else:
      return False

  def __repr__(self):
    return "Block<index: %s>, <hash: %s>" % (self.index, self.hash)

  def __eq__(self, other):
    return (self.index == other.index and
       self.timestamp == other.timestamp and
       self.prev_hash == other.prev_hash and
       self.hash == other.hash and
       self.data == other.data and
       self.nonce == other.nonce)

  def __ne__(self, other):
    return not self.__eq__(other)

  def __gt__(self, other):
    return self.timestamp < other.timestamp

  def __lt__(self, other):
    return self.timestamp > other.timestamp

