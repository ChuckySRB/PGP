from implementation.keymanagement.keymanager import *
from .message import *
from .filereader import *

class MessageManager:

    @staticmethod
    def send(path, email, message, private_key, public_key, authentification, privacy_algorthm, ZIP, RADIX):
        km, msg = KeyManager.get_key_manager("mika", "mika@gmail.com")
        km2, msg2 = KeyManager.get_key_manager("zika", "zika@gmail.com")
        if not km:
            print(msg)
            return
        km.gen_keys(1024, "RSA", "123")
        km2.gen_keys(1024, "RSA", "233")

        keys1, msg = KeyManager.get_keypair("mika@gmail.com")
        keys2, msg2 = KeyManager.get_keypair("zika@gmail.com")
        if not keys1:
            print(msg)
            return
        algorithms = MessageAlgorithms(authentification, privacy_algorthm, ZIP, RADIX, email)
        body = MessageBody("message.pgp", message)
        encryptor = MessageEncryptor(algorithms, body)
        encryptor.EncryptMessage(keys1[0].serialized_key, keys1[1].get_parameters()["id"], keys2[1].key)

        MessageFileReader.Send(path, "message", encryptor.message)

        message_b, msg = MessageFileReader.Read(path+"/message.pgp")
        print(msg)
        decryptor = MessageDecryptor(message_b)
        decryptor.DencryptMessage(keys2[0].serialized_key)

        print(decryptor.body.body)

    def read(self):
        pass