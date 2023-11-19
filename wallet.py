import base58
from Crypto.PublicKey import RSA

from utils import calculate_hash


class Owner:
    def __init__(self, private_key: RSA.RsaKey, public_key: bytes, bitcoin_address: bytes):
        self.private_key = private_key
        self.public_key = public_key
        self.bitcoin_address = bitcoin_address


def initialize_wallet():
    private_key = RSA.generate(2048)
    public_key = private_key.publickey().export_key()
    hash_1 = calculate_hash(public_key, hash_function="sha256")
    hash_2 = calculate_hash(hash_1, hash_function="ripemd160")
    bitcoin_address = base58.b58encode(hash_2)
    return Owner(private_key, public_key, bitcoin_address)