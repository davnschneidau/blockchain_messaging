from block import Block
import mine
from flask import Flask, jsonify, request
import sync
import requests
import os
import json
import sys
import apscheduler
import argparse
from message import Message
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

import utils
from config import *

node = Flask(__name__)

sync.sync(save=True) #want to sync and save the overall "best" blockchain from peers

from apscheduler.schedulers.background import BackgroundScheduler
sched = BackgroundScheduler(standalone=True)
CURRENT_BLOCK = None


def load_sender_keys():
  try:
      # Attempt to load the private key from a file
      with open("private_key.pem", "rb") as key_file:
          private_key = serialization.load_pem_private_key(
              key_file.read(),
              password=None,
          )

      # Load the corresponding public key
      public_key = private_key.public_key()
      return private_key, public_key
  except (FileNotFoundError, ValueError):
      # If the file doesn't exist or is invalid, generate new keys and save them
      private_key, public_key = rsa.generate_private_key(
          public_exponent=65537,
          key_size=2048,
      )

      with open("private_key.pem", "wb") as key_file:
          key_file.write(
              private_key.private_bytes(
                  encoding=serialization.Encoding.PEM,
                  format=serialization.PrivateFormat.PKCS8,
                  encryption_algorithm=serialization.NoEncryption(),
              )
          )

      with open("public_key.pem", "wb") as key_file:
          key_file.write(
              public_key.public_bytes(
                  encoding=serialization.Encoding.PEM,
                  format=serialization.PublicFormat.SubjectPublicKeyInfo,
              )
          )

      return private_key, public_key

# Load the sender's private key and corresponding public key
sender_private_key, sender_public_key = load_sender_keys()


@node.route('/blockchain.json', methods=['GET'])
def blockchain():
  local_chain = sync.sync_local() #update if they've changed
  # Convert our blocks into dictionaries
  # so we can send them as json objects later
  json_blocks = json.dumps(local_chain.block_list_dict())
  return json_blocks

@node.route('/mined', methods=['POST'])
def mined():
  possible_block_dict = request.get_json()
  print(possible_block_dict)
  print(sched.get_jobs())
  print(sched)

  sched.add_job(mine.validate_possible_block, args=[possible_block_dict], id='validate_possible_block') #add the block again

  return jsonify(received=True)

@node.route('/send/encrypted_message', methods=['POST'])
def send_encrypted_message():
  sender_address = request.form['sender_address']
  recipient_address = request.form['recipient_address']
  content = request.form['content']
  signature = request.form['signature']

  if CURRENT_BLOCK is None:
        CURRENT_BLOCK = Block()

  # Create a new Message object and add it to the blockchain
  message = Message(sender_address, sender_private_key, recipient_address, content)
  signature = message.sign_message()
  CURRENT_BLOCK.add_encrypted_message(sender_address, recipient_address, content, signature)

  return "Message sent successfully"

@node.route('/get/encrypted_messages', methods=['GET'])
def get_encrypted_messages():
    # Retrieve encrypted messages from the blockchain and display them
    messages = []
    for block in blockchain.chain:
        for message in block.encrypted_messages:
            messages.append({
                'sender_address': message['sender_address'],
                'recipient_address': message['recipient_address'],
                'content': message['content']
            })
    return jsonify(messages=messages)



if __name__ == '__main__':

  #args!
  parser = argparse.ArgumentParser(description='JBC Node')
  parser.add_argument('--port', '-p', default='5000',
                    help='what port we will run the node on')
  parser.add_argument('--mine', '-m', dest='mine', action='store_true')
  args = parser.parse_args()

  filename = '%sdata.txt' % (CHAINDATA_DIR)
  with open(filename, 'w') as data_file:
    data_file.write("Mined by node on port %s" % args.port)

  mine.sched = sched #to override the BlockingScheduler in the
  #only mine if we want to
  if args.mine:
    #in this case, sched is the background sched
    sched.add_job(mine.mine_for_block, kwargs={'rounds':STANDARD_ROUNDS, 'start_nonce':0}, id='mining') #add the block again
    sched.add_listener(mine.mine_for_block_listener, apscheduler.events.EVENT_JOB_EXECUTED)#, args=sched)

  sched.start() #want this to start so we can validate on the schedule and not rely on Flask

  #now we know what port to use
  node.run(host='127.0.0.1', port=args.port)

