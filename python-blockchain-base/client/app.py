import binascii
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import hashes
from flask import Flask, jsonify, request, render_template

from transaction import Transaction

# Initialize Flask app
app = Flask(__name__)

@app.route("/")
def index():
    return render_template("index.html")

@app.route("/make/transaction")
def make_transaction():
    return render_template("make_transaction.html")

@app.route("/view/transactions")
def view_transaction():
    return render_template("view_transactions.html")

@app.route("/wallet/new", methods=["GET"])
def new_wallet():
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=1024,
    )
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption()
    )
    public_key = private_key.public_key()
    public_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    
    response = {
        "private_key": binascii.hexlify(private_pem).decode("ascii"),
        "public_key": binascii.hexlify(public_pem).decode("ascii"),
    }

    return jsonify(response), 200

@app.route("/generate/transaction", methods=["POST"])
def generate_transaction():
    sender_address = request.form["sender_address"]
    sender_private_key = request.form["sender_private_key"]
    recipient_address = request.form["recipient_address"]
    value = request.form["amount"]

    transaction = Transaction(
        sender_address, sender_private_key, recipient_address, value
    )

    response = {
        "transaction": transaction.to_dict(),
        "signature": transaction.sign_transaction(),
    }

    return jsonify(response), 200

if __name__ == "__main__":
    app.run(
        host='127.0.0.1',
        port='5000',
        debug='True',
    )
