import implementation.configuration as config

import cryptography.hazmat.primitives.asymmetric.rsa as rsa
import cryptography.hazmat.primitives.asymmetric.dsa as dsa
import lib.myelgamal as elgamal
#import Crypto.PublicKey.ElGamal as elgamal
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.exceptions import InvalidSignature

class KeyGenerator:

    @staticmethod
    def generate_keys(algorithm: str, size: int):
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
            private_key = dsa.generate_private_key(key_size = size)
            public_key  = private_key.public_key()
        else:
            private_key = elgamal.Elgamal.generate_private_key(key_size= size)
            public_key = private_key.public_key

        return private_key, public_key

if __name__ == "__main__":
    private_key : elgamal.ElgamalPrivateKey = None
    public_key : elgamal.ElgamalPublicKey = None
    private_key, public_key = KeyGenerator.generate_keys("RSA", 1024)

    msg: str = "Hej, ja sam miki"

    res_msg = bytes(msg, 'utf-8')
    print(res_msg)

    # print(str(hex(public_key.public_numbers().n)))
    # print(len(str(hex(public_key.public_numbers().n))))
    # print(public_key.public_bytes(encoding=serialization.Encoding.PEM,
    #                                   format=serialization.PublicFormat.SubjectPublicKeyInfo))

    # print(len(public_key.public_bytes(encoding= serialization.Encoding.PEM, format=serialization.PublicFormat.SubjectPublicKeyInfo)))


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

    private_key, public_key = KeyGenerator.generate_keys("DSA", 2048)

    msg = "Hej ja nisam miki"
    res_msg = bytes(msg, 'utf-8')
    print(res_msg)

    signature = private_key.sign(
        data=res_msg,
        algorithm=hashes.SHA1()
    )

    #ako je data prevelika, moze se hashovati odvojeno

    try:
        public_key.verify(signature=signature, data=res_msg, algorithm=hashes.SHA1())
        print("Signature all cool!")
    except InvalidSignature:
        print("Signature not ok!")



    private_key, public_key = KeyGenerator.generate_keys("ElGamal", 1024)
    msg = "Opa, pa skoro sve radi"
    res_msg = bytes(msg, 'utf-8')
    print(res_msg)

    ciphertext = public_key.encrypt(res_msg)


    print(ciphertext)
    decodedText = private_key.decrypt(ciphertext)
    print(decodedText)

