import implementation.configuration as config

import cryptography.hazmat.primitives.asymmetric.rsa as rsa
import cryptography.hazmat.primitives.asymmetric.dsa as dsa
#import Crypto.PublicKey.ElGamal as elgamal
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes
from implementation.keygen.keygen import KeyGenerator
import lib.myelgamal as elgamal
from implementation.keymanagement.keywrapper.keywrapper import KeyWrapper

#Vidi posle kako ces sa greskom
class KeyManager:
    KEY_MANAGER_DICT: dict = dict()
    @staticmethod
    def get_key_manager(name: str, email: str):
        if email in KeyManager.KEY_MANAGER_DICT:
            if KeyManager.KEY_MANAGER_DICT[email].name != name:
                print("Error, names don't match!")
                return [None, "LOGIN FAILED, NAMES DO NOT MATCH"]
        else:
            KeyManager.KEY_MANAGER_DICT[email] = KeyManager(name, email)

        return [KeyManager.KEY_MANAGER_DICT[email], "OK"]

    def __init__(self, name: str, email: str):
        self.name: str = name
        self.email: str = email
        self.key_dict: dict = {}

    def gen_keys(self, key_size: int, algorithm: str, password: str):
        unique: bool = False
        private_key_wrapper: KeyWrapper = None
        public_key_wrapper: KeyWrapper = None
        while not unique:
            private_key, public_key = KeyGenerator.generate_keys(algorithm, key_size)

            private_key_wrapper, public_key_wrapper = KeyWrapper.generate_keys(algorithm, key_size, password, private_key, public_key)
            if public_key_wrapper.get_parameters()["id"] not in self.key_dict.keys():
                unique = True
        self.key_dict[public_key_wrapper.get_parameters()["id"]] = (private_key_wrapper, public_key_wrapper)

    def get_keys(self):
        return self.key_dict




if __name__ == "__main__":

    first, msg1 = KeyManager.get_key_manager("mika", "mika@gmail.com")
    second, msg2 = KeyManager.get_key_manager("zika", "zika@gmail.com")
    third, msg3 = KeyManager.get_key_manager("zujka", "mika@gmail.com")

    print(msg1)
    print(msg2)
    print(msg3)

    print(len(KeyManager.KEY_MANAGER_DICT))


