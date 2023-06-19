from implementation.keymanagement.keymanager import *
from .message import *
from .filereader import *

class MessageManager:

    @staticmethod
    def send(path, email_reciever, email_sender, password, message, private_key_ID, public_key_ID, authentification, privacy, ZIP, RADIX):

        algorithms = MessageAlgorithms(authentification, privacy, ZIP, RADIX, email_sender)
        body = MessageBody("message.pgp", message)
        encryptor = MessageEncryptor(algorithms, body, private_key_ID, public_key_ID, password, email_reciever)
        encryptor.EncryptMessage()

        MessageFileReader.Send(path, "message", encryptor.message)

        print (MessageManager.read(email_reciever, password, path+"/message.pgp"))

    @staticmethod
    def read(user_email, password, file_path):

        message_b, msg = MessageFileReader.Read(file_path)
        print(msg)

        if not message_b:
            return msg

        decryptor = MessageDecryptor(message_b, user_email, password)
        decryptor.DencryptMessage()

        if decryptor.body:
            return decryptor.body.data

        return "Fail"

