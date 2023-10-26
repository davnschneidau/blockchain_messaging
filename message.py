from cryptography.hazmat.primitives.asymmetric import rsa, padding, utils
from cryptography.hazmat.primitives import serialization, hashes
import binascii
import json

class Message:
    def __init__(self, sender_address, sender_private_key, recipient_address, content):
        self.sender_address = sender_address
        self.recipient_address = recipient_address
        self.content = content
        self.sender_private_key = sender_private_key

    def sign_message(self):
        #implement a method to sign the message
        data = json.dumps({
            "sender_address": self.sender_address,
            "recipient_address": self.recipient_address,
            "content": self.content
        }, sort_keys=True).encode('utf-8')
        signature = self.sender_private_key.sign(
            data,
            padding.PKCS1v15(),
            hashes.SHA256()
        )
        return binascii.hexlify(signature).decode('ascii')