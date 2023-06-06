from abc import ABC, abstractmethod

from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric import dsa
import lib.myelgamal as elgamal
import implementation.configuration as config
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes
from cryptography.exceptions import InvalidSignature

ID_MASK: int = (1 << 64) - 1

class UnsupportedKeyOperation(Exception):
    "Raised when calling an unsupported key operation"
    pass

class KeyWrapper(ABC):

    @abstractmethod
    def get_parameters(self):
        pass

    @abstractmethod
    def get_algorithm(self):
        pass

    @abstractmethod
    def is_private(self):
        pass

    @abstractmethod
    def is_signature(self):
        pass

    @abstractmethod
    def is_encryption(self):
        pass

    @abstractmethod
    def encrypt(self, msg: bytes) -> bytes:
        pass

    @abstractmethod
    def decrypt(self, msg: bytes) -> bytes:
        pass

    @abstractmethod
    def sign(self, msg: bytes) -> bytes:
        pass

    @abstractmethod
    def verify(self, msg: bytes, signature: bytes) -> bool:
        pass

class RSAPublicKeyWrapper(KeyWrapper):

    def __init__(self, public_key: rsa.RSAPublicKey, key_size):
        super().__init__()
        self.size: int = key_size
        self.key: rsa.RSAPublicKey = public_key
        self.id: int = public_key.public_numbers().n & ID_MASK

    def get_parameters(self):
        return {'e': self.key.public_numbers().e, 'n': self.key.public_numbers().n, 'id': self.id}

    def is_private(self):
        return False

    def get_algorithm(self):
        return "RSA"

    def is_signature(self):
        return True

    def is_encryption(self):
        return True

    def encrypt(self, msg: bytes) -> bytes:
        ciphertext: bytes = self.key.encrypt(msg, padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        ))
        return ciphertext

    def decrypt(self, msg: bytes) -> bytes:
        raise UnsupportedKeyOperation

    def sign(self, msg: bytes) -> bytes:
        raise UnsupportedKeyOperation

    def verify(self, msg: bytes, signature: bytes) -> bool:
        try:
            self.key.verify(signature= signature, data= msg,
                            padding= padding.PSS(
                                mgf= padding.MGF1(hashes.SHA256()),
                                salt_length= padding.PSS.MAX_LENGTH
                            ),
                            algorithm= hashes.SHA256()
                            )
        except InvalidSignature:
            return False
        return True


if __name__ == "__main__":

    private_rsa: rsa.RSAPrivateKey = rsa.generate_private_key(public_exponent=config.rsa_public_exponent ,key_size=1024)
    public_rsa: rsa.RSAPublicKey = private_rsa.public_key()

    rsa_public_wrapper: RSAPublicKeyWrapper = RSAPublicKeyWrapper(public_rsa, 1024)
    print(rsa_public_wrapper.get_parameters())

    msg_str: str = 'Ja saaaaam'
    msg: bytes = bytes(msg_str, 'utf-8')

    # cipher: bytes = rsa_public_wrapper.encrypt(msg)

    # res: bytes = private_rsa.decrypt(cipher,  padding.OAEP(
    #     mgf=padding.MGF1(algorithm=hashes.SHA256()),
    #     algorithm=hashes.SHA256(),
    #     label=None
    # ))
    #
    # print("Cool") if res == msg else print("Not cool")
    #
    signature: bytes = private_rsa.sign(msg, padding.PSS(
        mgf= padding.MGF1(hashes.SHA256()),
        salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )

    print("Cool") if rsa_public_wrapper.verify(msg, signature) else print("Not cool")