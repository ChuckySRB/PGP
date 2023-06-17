from implementation.keymanagement.keymanager import *


class MessageEncryption:

    @staticmethod
    def encrypt(email, private_key, public_key, authentification, privacy_algorthm, ZIP, RADIX):
        keyManager = KeyManager()
