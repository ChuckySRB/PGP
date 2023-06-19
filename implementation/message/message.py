import base64
import time
import pickle
import hashlib
import io
import zipfile
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
#from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend
import os
from implementation.keymanagement.keymanager import *


# Izdelio sam klase kako bih ih lakše upakovao u bajtove po redosledu u kom se pakuju

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
# Tri iznad su osnovne strukture sa slike sa slajdova

# Ove ispod su spakovane strukture koje se pojavljuju tokom sifrovanja
class MessageAlgorithms():
    def __init__(self, authentification, encryption, zip, radix64, email):
        self.authentificaton = authentification
        self.encryption = encryption
        self.zip = zip
        self.radix64 = radix64
        self.email = email

class MessageBodyAndHeader():
    def __init__(self, body, header):
        self.body = body
        self.header = header

class Message():
    def __init__(self, body_and_header, session_key):
        self.body_and_header = body_and_header
        self.session_key = session_key

class MessageFinal():
    def __init__(self, message, algorithms):
        self.algorithms = algorithms
        self.message = message

class MessageEncryptor():

    def __init__(self, algorithms: MessageAlgorithms, message: MessageBody, private_key_ID, public_key_ID, password, reciever_email):
        self.message: bytes = b''
        self.algorithms = algorithms
        self.body: MessageBody = message
        self.manager = KeyManager.get_manager(algorithms.email)
        self.encryption_key = None
        self.signed_key = None
        self.reciever_key = None
        if self.manager:
            self.encryption_key = self.manager.get_keys_withID(int(private_key_ID))[0]
            self.signed_key = self.manager.get_keys_withID(int(public_key_ID))[0]
        manager = KeyManager.get_manager(reciever_email)
        if manager:
            for key in list(manager.key_dict.values()):
                if key[1].is_encryption():
                    self.reciever_key = key[1]
                    break
        self.password = password

    def Sign(self, auth, message):
        if not auth or len(auth)==0:
            return None
        else:
        # Hashovanje poruke pomocu SHA-256

            potpis = self.signed_key.sign(message, self.password)

            header = MessageSignature(self.signed_key.id, "two_bytes", potpis)

            return header

    def Encrypt(self, algorithm):
        session_key = os.urandom(16)
        if algorithm and self.reciever_key:
            cipher = Cipher(algorithms.AES(session_key), modes.ECB(), backend=default_backend())
        else:
            print("No Encryption")
            return None
        encryptor = cipher.encryptor()
        encrypthed_message = encryptor.update(self.message) + encryptor.finalize()


        encrypthed_session_key = self.reciever_key.encrypt(session_key)

        session_key_header = MessageSessionKey(self.reciever_key.id, encrypthed_session_key)
        self.message = encrypthed_message

        return session_key_header

    def Radix(self):
        self.message = base64.b64encode(self.message)

    def Zip(self):
        # Create an in-memory buffer
        zip_buffer = io.BytesIO()

        # Create a ZipFile object with the buffer
        with zipfile.ZipFile(zip_buffer, 'w', zipfile.ZIP_DEFLATED) as zip_file:
            # Add the data to the zip file
            zip_file.writestr('data', self.message)

        # Get the compressed bytes
        self.message = zip_buffer.getvalue()

    def EncryptMessage(self):

        # Pretvaranje tela poruke + zaglavlje u bytove
        body_header = MessageBodyAndHeader(body = self.body,header= self.Sign(self.algorithms.authentificaton, pickle.dumps(self.body)))

        self.messsage = pickle.dumps(body_header)

        # Zipovanje tela+zaglavlja
        if self.algorithms.zip:
            self.Zip()

        # Sifrovanje zipovane poruke zajedno sa kljucem sesije
        session_key_header = self.Encrypt(self.algorithms.encryption)
        self.message = pickle.dumps(Message(self.message, session_key_header))

        # Radix64 konvercija cele poruke
        if self.algorithms.radix64:
            self.Radix()

        # Pakovanje koriscenih algoritama zajedno sa porukom kao uputsvo za dekripciju
        self.message = pickle.dumps(MessageFinal(self.message, algorithms= self.algorithms))


class MessageDecryptor():

    def __init__(self, message: bytes, email, password):
        self.message = message
        self.email = email
        self.password = password
        self.algorithms = None
        self.body = None
        self.manager = KeyManager.get_manager(email)
        self.signed_key = None
        self.reciever_key = None

    def Authenticate(self, auth, header):
        if not auth:
            return True
        else:

            manager = KeyManager.get_manager(self.algorithms.email)
            if not manager:
                return

            self.reciever_key = manager.get_keys_withID(int(header.A_public_key_ID))[1]

            return self.reciever_key.verify(pickle.dumps(self.body), header.message_digest)


    def Decrypt(self, algorithm, session_key, A_private_key):

        if not session_key or not self.manager:
            return

        # Trazedje Kljuca

        if self.manager:
            self.decryption_key = self.manager.get_keys_withID(int(session_key.B_public_key_ID))[0]
        Ks = self.decryption_key.decrypt(session_key.session_key)

        cipher = Cipher(algorithms.AES(Ks), modes.ECB(), backend=default_backend())
        decryptor = cipher.decryptor()
        decrypthed_message = decryptor.update(self.message) + decryptor.finalize()

        self.message = decrypthed_message

    def EnRadix(self):
        self.message = base64.b64decode(self.message)

    def UnZip(self, message):
        # Create an in-memory zip file
        zip_buffer = io.BytesIO(message)

        # Create a ZipFile object with the buffer
        with zipfile.ZipFile(zip_buffer, 'r', zipfile.ZIP_DEFLATED) as zip_file:
            # Extract the data from the zip file
            extracted_data = zip_file.read('data')

        return extracted_data

    def DencryptMessage(self):

        # Raspakovati koriscene algoritme zajedno sa porukom
        poruka_algo = pickle.loads(self.message)

        self.message = poruka_algo.message
        self.algorithms = poruka_algo.algorithms

        # Radix64 konvercija cele poruke
        if self.algorithms.radix64:
            self.EnRadix()

        # Sifrovanje zipovane poruke zajedno sa kljucem sesije
        message = pickle.loads(self.message)
        self.message = message.body_and_header
        self.Decrypt(self.algorithms.encryption, message.session_key)

        # Unzipovanje tela+zaglavlja
        if self.algorithms.zip:
            self.message = self.UnZip(self.message)

        # Raspakovanje porukke
        body_header: MessageBodyAndHeader = pickle.loads(self.message)
        self.body = body_header.body

        # Provera potpisa poruke
        return self.Authenticate(self.algorithms.authentificaton, body_header.header)










