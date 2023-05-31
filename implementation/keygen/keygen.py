import implementation.configuration as config

import cryptography.hazmat.primitives.asymmetric.rsa as rsa
import cryptography.hazmat.primitives.asymmetric.dsa as dsa
import Crypto.PublicKey.ElGamal as elgamal
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes
class KeyGenerator:

    @staticmethod
    def generate_keys(name: str, email: str, algorithm: str, size: int):
        if size != 1024 and size != 2048:
            print("Nedozvoljena velicina kljuca")
            return None

        if algorithm not in config.asymmetric_algorithms:
            print(f"{algorithm} nije u dozvoljenoj grupi algoritama")

        private_key = None
        public_key = None
        if algorithm == "RSA":
            private_key = rsa.generate_private_key(public_exponent= config.rsa_public_exponent, key_size = size)
            public_key = private_key.public_key()


        elif algorithm == "DSA":
            pass
        else:
            pass

        return private_key, public_key

if __name__ == "__main__":
    private_key : rsa.RSAPrivateKey = None
    public_key : rsa.RSAPublicKey = None
    private_key, public_key = KeyGenerator.generate_keys("miki","mejl", "RSA", 1024)

    msg: str = "Hej, ja sam miki"

    res_msg = bytes(msg, 'utf-8')
    print(res_msg)

    ciphertext = public_key.encrypt(res_msg,
                       padding.OAEP(mgf = padding.MGF1(algorithm=hashes.SHA256()),
                                    algorithm=hashes.SHA256(),
                                    label = None
                                    )
                       )
    print(ciphertext)

    plaintext = private_key.decrypt(ciphertext,
                                    padding.OAEP(
                                        mgf=padding.MGF1(algorithm=hashes.SHA256()),
                                        algorithm=hashes.SHA256(),
                                        label=None
                                    ))
    print(plaintext)
    print(plaintext.decode('utf-8'))




