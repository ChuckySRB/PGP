from abc import ABC, abstractmethod

from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric import dsa
import lib.myelgamal as elgamal
import implementation.configuration as config
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
import hashlib

ID_MASK: int = (1 << 64) - 1

class UnsupportedKeyOperation(Exception):
    "Raised when calling an unsupported key operation"
    pass

class IncorrectKeyPassword(Exception):
    "Raised when private key called with wrong password"
    pass

class KeyWrapper(ABC):

    @abstractmethod
    def get_parameters(self, password: str = None):
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
    def decrypt(self, msg: bytes, password: str) -> bytes:
        pass

    @abstractmethod
    def sign(self, msg: bytes, password: str) -> bytes:
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

    def get_parameters(self, password: str = None):
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
        i: int = 0
        size_one: int = (self.size // 8) - 70 #Neka moja racunica
        ciphertext: bytes = b''
        zero: int = 0
        for i in range(0, len(msg), size_one):
            boundary: int = i + size_one
            if (i + size_one > len(msg)):
                boundary = len(msg)
            res_bytes: bytes = self.key.encrypt(msg[i:boundary], padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            ))

            res_bytes = (self.size // 8 - len(res_bytes)) * zero.to_bytes(1, "big") + res_bytes
            ciphertext += res_bytes
        return ciphertext

    def decrypt(self, msg: bytes, password: str) -> bytes:
        raise UnsupportedKeyOperation

    def sign(self, msg: bytes, password: str) -> bytes:
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

class RSAPrivateKeyWrapper(KeyWrapper):
    def __init__(self, private_key: rsa.RSAPrivateKey, size: int, password: str):
        super().__init__()
        self.size: int = size
        self.hashed_password = hashlib.sha1(password.encode(encoding='utf-8'))
        self.id: int = private_key.public_key().public_numbers().n & ID_MASK
        self.serialized_key:bytes = private_key.private_bytes(
            encoding= serialization.Encoding.PEM,
            format= serialization.PrivateFormat.PKCS8,
            encryption_algorithm= serialization.BestAvailableEncryption(bytes(password, 'utf-8'))
        )


    def _decrypt_private_key(self, password: str) -> rsa.RSAPrivateKey:
        if self.hashed_password.hexdigest() != hashlib.sha1(password.encode(encoding='utf-8')).hexdigest():
            raise IncorrectKeyPassword

        private_key: rsa.RSAPrivateKey = serialization.load_pem_private_key(
            self.serialized_key, password= (bytes(password, 'utf-8'))
        )

        return private_key

    def get_parameters(self, password: str = None):
        if password is None:
            raise IncorrectKeyPassword
        private_key: rsa.RSAPrivateKey = self._decrypt_private_key(password)
        return {'d': private_key.private_numbers().d, 'n': private_key.private_numbers().p * private_key.private_numbers().q, 'id': self.id}

    def is_private(self):
        return True

    def get_algorithm(self):
        return "RSA"

    def is_signature(self):
        return True

    def is_encryption(self):
        return True

    def decrypt(self, msg: bytes, password: str) -> bytes:
        private_key: rsa.RSAPrivateKey = self._decrypt_private_key(password)

        plaintext: bytes = b''
        one_size: int = self.size // 8
        for i in range(0, len(msg), one_size):
            boundary: int = i + one_size
            if(boundary > len(msg)):
                boundary = len(msg)
            plaintext += private_key.decrypt(msg[i:boundary], padding.OAEP(
                mgf = padding.MGF1(algorithm= hashes.SHA256()),
                algorithm= hashes.SHA256(),
                label=None
            ))
        return plaintext


    def encrypt(self, msg: bytes) -> bytes:
        raise UnsupportedKeyOperation

    def sign(self, msg: bytes, password: str) -> bytes:
        private_key: rsa.RSAPrivateKey = self._decrypt_private_key(password)

        signature: bytes = private_key.sign(msg, padding.PSS(
                                                mgf= padding.MGF1(hashes.SHA256()),
                                                salt_length= padding.PSS.MAX_LENGTH
                                            ),
                                            hashes.SHA256())
        return signature

    def verify(self, msg: bytes, signature: bytes) -> bool:
        raise UnsupportedKeyOperation

class DSAPublicKeyWrapper(KeyWrapper):

    def __init__(self, public_key: dsa.DSAPublicKey, key_size: int):
        super().__init__()
        self.key = public_key
        self.size = key_size
        self.id = self.key.public_numbers().y & ID_MASK

    def get_parameters(self, password: str = None):
        return {'y': self.key.public_numbers().y, 'p': self.key.public_numbers().parameter_numbers.p,
                'q': self.key.public_numbers().parameter_numbers.q,
                'g': self.key.public_numbers().parameter_numbers.g,
                'id': self.id
                }

    def is_private(self):
        return False

    def is_signature(self):
        return True

    def is_encryption(self):
        return False

    def get_algorithm(self):
        return "DSA"

    def encrypt(self, msg: bytes) -> bytes:
        raise UnsupportedKeyOperation

    def decrypt(self, msg: bytes, password: str) -> bytes:
        raise UnsupportedKeyOperation

    def sign(self, msg: bytes, password: str) -> bytes:
        raise UnsupportedKeyOperation

    def verify(self, msg: bytes, signature: bytes) -> bool:
        try:
            self.key.verify(
                signature,
                msg,
                hashes.SHA256()
            )
        except InvalidSignature:
            return False
        return True

class DSAPrivateKeyWrapper(KeyWrapper):

    def __init__(self, private_key: dsa.DSAPrivateKey, size: int, password: str):
        super().__init__()
        self.size: int = size
        self.hashed_password = hashlib.sha1(password.encode(encoding='utf-8'))
        self.id: int = private_key.public_key().public_numbers().y & ID_MASK
        self.serialized_key: bytes = private_key.private_bytes(
            encoding= serialization.Encoding.PEM,
            format= serialization.PrivateFormat.PKCS8,
            encryption_algorithm= serialization.BestAvailableEncryption(bytes(password, 'utf-8'))
        )

    def _decrypt_private_key(self, password: str) -> dsa.DSAPrivateKey:
        if self.hashed_password.hexdigest() != hashlib.sha1(password.encode('utf-8')).hexdigest():
            raise IncorrectKeyPassword
        private_key : dsa.DSAPrivateKey = serialization.load_pem_private_key(
            self.serialized_key, password= (bytes(password, 'utf-8'))
        )
        return private_key

    def get_parameters(self, password: str = None):
        if password is None:
            raise IncorrectKeyPassword
        private_key: dsa.DSAPrivateKey = self._decrypt_private_key(password)
        return {'x': private_key.private_numbers().x, 'id': self.id }

    def is_private(self):
        return True

    def get_algorithm(self):
        return "DSA"

    def is_signature(self):
        return True

    def is_encryption(self):
        return False

    def decrypt(self, msg: bytes, password: str) -> bytes:
        raise UnsupportedKeyOperation

    def encrypt(self, msg: bytes) -> bytes:
        raise UnsupportedKeyOperation

    def sign(self, msg: bytes, password: str) -> bytes:
        private_key: dsa.DSAPrivateKey = self._decrypt_private_key(password)

        signature: bytes = private_key.sign(
            msg,
            hashes.SHA256()
        )

        return signature

    def verify(self, msg: bytes, signature: bytes) -> bool:
        raise UnsupportedKeyOperation

class ElgamalPublicKeyWrapper(KeyWrapper):

    def __init__(self, public_key: elgamal.ElgamalPublicKey, key_size):
        super().__init__()
        self.size: int = key_size
        self.key: elgamal.ElgamalPublicKey = public_key
        self.id = public_key.q & ID_MASK

    def get_parameters(self, password: str = None):
        return { 'q': self.key.q, 'a': self.key.a, 'Ya': self.key.Ya, 'id': self.id }

    def is_private(self):
        return False

    def is_encryption(self):
        return True

    def is_signature(self):
        return False

    def get_algorithm(self):
        return "Elgamal"

    def encrypt(self, msg: bytes) -> bytes:
        return self.key.encrypt(msg)

    def decrypt(self, msg: bytes, password: str) -> bytes:
        raise UnsupportedKeyOperation

    def sign(self, msg: bytes, password: str) -> bytes:
        raise UnsupportedKeyOperation

    def verify(self, msg: bytes, signature: bytes) -> bool:
        raise UnsupportedKeyOperation

class ElgamalPrivateKeyWrapper(KeyWrapper):

    def __init__(self, private_key: elgamal.ElgamalPrivateKey, size: int, password: str):
        super().__init__()
        self.size: int = size
        self.hashed_password = hashlib.sha1(password.encode(encoding='utf-8'))
        self.id = private_key.q & ID_MASK
        self.serialized_key = private_key.private_bytes(password=password)
        # print(self.serialized_key)

    def _decrypt_private_key(self, password: str) -> elgamal.ElgamalPrivateKey:
        if self.hashed_password.hexdigest() != hashlib.sha1(password.encode('utf-8')).hexdigest():
            raise IncorrectKeyPassword

        return elgamal.Elgamal.load_pem_private_key(self.serialized_key, password)

    def get_parameters(self, password:str = None):
        if password is None:
            raise IncorrectKeyPassword

        private_key: elgamal.ElgamalPrivateKey = self._decrypt_private_key(password)

        return {'q': private_key.q, 'a': private_key.a, 'Xa': private_key.Xa, 'id': self.id }

    def is_private(self):
        return True

    def is_signature(self):
        return False

    def is_encryption(self):
        return True

    def get_algorithm(self):
        return "Elgamal"

    def decrypt(self, msg: bytes, password: str) -> bytes:
        private_key: elgamal.ElgamalPrivateKey = self._decrypt_private_key(password)

        return private_key.decrypt(msg)

    def encrypt(self, msg: bytes) -> bytes:
        raise UnsupportedKeyOperation

    def sign(self, msg: bytes, password: str) -> bytes:
        raise UnsupportedKeyOperation

    def verify(self, msg: bytes, signature: bytes) -> bool:
        raise UnsupportedKeyOperation


if __name__ == "__main__":

    private_rsa: rsa.RSAPrivateKey = rsa.generate_private_key(public_exponent=config.rsa_public_exponent ,key_size=1024)
    public_rsa: rsa.RSAPublicKey = private_rsa.public_key()

    rsa_public_wrapper: RSAPublicKeyWrapper = RSAPublicKeyWrapper(public_rsa, 1024)
    rsa_private_wrapper: RSAPrivateKeyWrapper = RSAPrivateKeyWrapper(private_rsa, 1024, "Sifra")
    print(rsa_public_wrapper.get_parameters())
    print(rsa_private_wrapper.get_parameters("Sifra"))

    msg_str: str = 'Ja saaaaam' * 1000
    msg: bytes = bytes(msg_str, 'utf-8')

    cipher: bytes = rsa_public_wrapper.encrypt(msg)

    res = rsa_private_wrapper.decrypt(cipher, "Sifra")
    # print(res)
    print("Cool") if res == msg else print("Not cool")

    signature: bytes = rsa_private_wrapper.sign(msg, "Sifra")

    print("Cool") if rsa_public_wrapper.verify(msg, signature) else print("Not cool")

    private_dsa: dsa.DSAPrivateKey = dsa.generate_private_key(2048)
    public_dsa: dsa.DSAPublicKey = private_dsa.public_key()

    dsa_public_key_wrapper: DSAPublicKeyWrapper = DSAPublicKeyWrapper(public_dsa, 2048)
    dsa_private_key_wrapper: DSAPrivateKeyWrapper = DSAPrivateKeyWrapper(private_dsa, 2048, "Sifra123")
    print(dsa_public_key_wrapper.get_parameters())
    print(dsa_private_key_wrapper.get_parameters("Sifra123"))

    signature = dsa_private_key_wrapper.sign(msg, "Sifra123")



    print("Cool") if dsa_public_key_wrapper.verify(msg, signature) else print("Not cool")

    private_elgamal : elgamal.ElgamalPrivateKey = elgamal.Elgamal.generate_private_key(2048)
    public_elgamal : elgamal.ElgamalPublicKey = private_elgamal.public_key

    elgamal_private_key_wrapper : ElgamalPrivateKeyWrapper = ElgamalPrivateKeyWrapper(private_elgamal, 2048, "Sifra334")
    elgamal_public_key_wrapper : ElgamalPublicKeyWrapper = ElgamalPublicKeyWrapper(public_elgamal, 2048)
    print(elgamal_public_key_wrapper.get_parameters())
    print(elgamal_private_key_wrapper.get_parameters("Sifra334"))

    cipher = elgamal_public_key_wrapper.encrypt(msg)

    print("Cool") if elgamal_private_key_wrapper.decrypt(cipher, "Sifra334") == msg else print("Not cool")