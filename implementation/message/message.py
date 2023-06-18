import time
import pickle

#Izdelio sam klase kako bih ih lakše upakovao u bajtove po redosledu u kom se pakuju


class MessageSessionKey():
    def __init__(self, B_public_key_ID, session_key):
        self.B_public_key_ID = B_public_key_ID
        self.session_key = session_key

class MessageSignature():
    def __init__(self, A_public_key_ID, twoB_message_digest, message_digest):
        self.timestamp = time.time()
        self.A_public_key_ID = A_public_key_ID
        self.twoB_message_digest = twoB_message_digest
        self.message_digest = message_digest

class MessageBody():
    def __init__(self, filename, data):
        self.filename = filename
        self.timestamp = time.time()
        self.data = data

class MessageAlgorithms():
    def __init__(self, authentification, encryption, zip, radix64):
        self.authentificaton = authentification
        self.encryption = encryption
        self.zip = zip
        self.radix64 = radix64

class MessageBodyAndHeader():
    def __init__(self, body: MessageBody, header):
        self.body = body
        self.header = header

class Message():
    def __init__(self, body_and_header: bytes, session_key):
        self.body_and_header = body_and_header
        self.session_key = session_key

class MessageFinal():
    def __init__(self, message: bytes, algorithms: MessageAlgorithms):
        self.algorithms = algorithms
        self.message = message

class MessageEncryptor():
    def __init__(self, algorithms: MessageAlgorithms, message: MessageBody, signature: MessageSignature ):
        self.algorithms = algorithms
        self.session_key: MessageSessionKey
        self.signature: MessageSignature
        self.body: MessageBody = message
        self.message: bytes = pickle.dumps(self.body)
        self.EncryptMessage()

    def Sign(self):

        pass
    def Encrypt(self):
        pass
    def Radix(self):
        pass
    def Zip(self):
        pass
    def EncryptMessage(self):
        if self.algorithms.authentificaton and len(self.algorithms.authentificaton) > 0:
            self.Sign()
        if self.algorithms.zip:
            self.Zip()
        if self.algorithms.encryption:
            self.Encrypt()
        if self.algorithms.radix64:
            self.Radix()

