from collections import OrderedDict
import binascii
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, utils
from cryptography.hazmat.primitives.serialization import load_pem_private_key

class Transaction:
    def __init__(self, sender_address, sender_private_key, recipient_address, value):
        self.sender_address = sender_address
        self.sender_private_key = sender_private_key
        self.recipient_address = recipient_address
        self.value = value

    def __getattr__(self, attr):
        return self.data[attr]

    def to_dict(self):
        return OrderedDict(
            {
                "sender_address": self.sender_address,
                "recipient_address": self.recipient_address,
                "value": self.value,
            }
        )

    def sign_transaction(self):
        """Sign transaction with private key"""
        private_key = load_pem_private_key(
            binascii.unhexlify(self.sender_private_key),
            password=None,
        )

        data_to_sign = str(self.to_dict()).encode("utf-8")
        signature = private_key.sign(
            data_to_sign,
            padding.PKCS1v15(),
            hashes.SHA256(),
            utils.Prehashed(hashes.SHA256()),
        )

        return binascii.hexlify(signature).decode("ascii")
