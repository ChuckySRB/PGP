from implementation.keymanagement.keymanager import *


class MessageEncryption:

    @staticmethod
    def encrypt(path, email, private_key, public_key, authentification, privacy_algorthm, ZIP, RADIX):
        km, msg = KeyManager.get_key_manager("mika", "mika@gmail.com")
        if not km:
            print(msg)
            return
        km.gen_keys(1024, "RSA", "123")
        B_public_key, message = KeyManager.get_public_key(email)
        if not B_public_key:
            print(message)
            return
        print(path)
        file = open(f"{path}/message.pem", "w")

        file.write("-----BEGIN PUBLIC KEy-----\n")
        file.write(f"{str(B_public_key)}\n")
        file.write("-----END PUBLIC KEy-----\n")
        file.close()
        print("Message sent!")