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
    def __init__(self, body: MessageBody, header: MessageSignature):
        self.body = body
        self.header = header

class Message():
    def __init__(self, body_and_header: bytes, session_key: MessageSessionKey):
        self.body_and_header = body_and_header
        self.session_key = session_key

class MessageFinal():
    def __init__(self, message: bytes, algorithms: MessageAlgorithms):
        self.algorithms = algorithms
        self.message = message

class MessageEncryptor():

    def __init__(self, algorithms: MessageAlgorithms, message: MessageBody):
        self.message: bytes = b''
        self.algorithms = algorithms
        self.body: MessageBody = message

    def Sign(self, auth, message, A_private_key, A_public_key_ID):
        if not auth or len(auth)==0:
            return None
        else:
        # Hashovanje poruke pomocu SHA-256
            hash_object = hashlib.sha256()
            hash_object.update(message)
            hash_result = hash_object.digest()

        # Enkriptovanje hesha pomocu CAST-128 i privatnog kljuca
            #iv = os.urandom(16)  # 16 bytes for CAST-128

            cipher = Cipher(algorithms.CAST5(A_private_key), modes.ECB(), backend=default_backend())
            encryptor = cipher.encryptor()
            encrypted_header = encryptor.update(hash_result) + encryptor.finalize()
            #encrypted_header = iv + encrypted_header
            encrypted_header = encrypted_header

            header = MessageSignature(A_public_key_ID, "two_bytes", encrypted_header)

            return header

    def Encrypt(self, algorithm, B_public_key):
        session_key = os.urandom(16)
        if algorithm == "AES128":
            cipher = Cipher(algorithms.AES(session_key), modes.ECB(), backend=default_backend())
            cipher_Ks = Cipher(algorithms.AES(B_public_key), modes.ECB(), backend=default_backend())
        elif algorithm == "Cas5":
            cipher = Cipher(algorithms.CAST5(session_key), modes.ECB(), backend=default_backend())
            cipher_Ks = Cipher(algorithms.AES(B_public_key), modes.ECB(), backend=default_backend())
        else:
            print("Bad Encryption Algorithm")
            return None
        encryptor = cipher.encryptor()
        encryptor_KS = cipher_Ks.encryptor()
        encrypthed_message = encryptor.update(self.message) + encryptor.finalize()
        encrypthed_session_key = encryptor_KS.update(session_key) + encryptor.finalize()

        session_key_header = MessageSessionKey(B_public_key, encrypthed_session_key)
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

    def EncryptMessage(self, A_private_key, A_public_key_ID, B_public_key):

        # Pretvaranje tela poruke + zaglavlje u bytove
        body_header = MessageBodyAndHeader(body = self.body,
                                           header= self.Sign(self.algorithms.authentificaton, pickle.dumps(self.body),
                                                             A_private_key, A_public_key_ID))
        self.messsage = pickle.dumps(body_header)

        # Zipovanje tela+zaglavlja
        if self.algorithms.zip:
            self.Zip()

        # Sifrovanje zipovane poruke zajedno sa kljucem sesije
        session_key_header = self.Encrypt(self.algorithms.encryption, B_public_key)
        self.message = pickle.dumps(Message(self.message, session_key_header))

        # Radix64 konvercija cele poruke
        if self.algorithms.radix64:
            self.Radix()

        # Pakovanje koriscenih algoritama zajedno sa porukom kao uputsvo za dekripciju
        self.message = pickle.dumps(MessageFinal(self.message, algorithms= self.algorithms))


class MessageDecryptor():

    def __init__(self, message: bytes):
        self.message = message
        self.algorithms = None
        self.body = None

    def Authenticate(self, auth, header):
        if not auth or len(auth) == 0:
            return True
        else:
            A_manager = KeyManager.get_manager(self.algorithms.email)
            if not A_manager:
                return False

            A_public_key_wrapper = A_manager.get_public_key_withID(header.A_public_key_ID)
            if not A_public_key_wrapper:
                return False

            A_public_key = A_public_key_wrapper.key

            cipher = Cipher(algorithms.CAST5(A_public_key), modes.ECB(), backend=default_backend())
            decryptor = cipher.decryptor()
            decrypted_header = decryptor.update(header.message_digest) + decryptor.finalize()

            hash_object = hashlib.sha256()
            hash_object.update(pickle.dumps(self.body))
            hash_result = hash_object.digest()

            return decrypted_header == hash_result

    def Decrypt(self, algorithm, session_key, A_private_key):

        if not session_key:
            return

        # Trazedje Kljuca

        if algorithm == "AES128":
            cipher_Ks = Cipher(algorithms.AES(A_private_key), modes.ECB(), backend=default_backend())
        elif algorithm == "Cas5":
            cipher_Ks = Cipher(algorithms.AES(A_private_key), modes.ECB(), backend=default_backend())
        else:
            print("Bad Encryption Algorithm")
            return

        decryptor_KS = cipher_Ks.decryptor()
        decrypthed_session_key = decryptor_KS.update(session_key.session_key) + decryptor_KS.finalize()

        if algorithm == "AES128":
            cipher = Cipher(algorithms.AES(decrypthed_session_key), modes.ECB(), backend=default_backend())
        else:
            cipher = Cipher(algorithms.CAST5(decrypthed_session_key), modes.ECB(), backend=default_backend())

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

    def DencryptMessage(self, B_private_key):

        # Raspakovati koriscene algoritme zajedno sa porukom
        poruka_algo: MessageFinal = pickle.loads(self.message)

        self.message = poruka_algo.message
        self.algorithms = poruka_algo.algorithms

        # Radix64 konvercija cele poruke
        if self.algorithms.radix64:
            self.EnRadix()

        # Sifrovanje zipovane poruke zajedno sa kljucem sesije
        message: Message = pickle.loads(self.message)
        self.message = message.body_and_header
        self.Decrypt(self.algorithms.encryption, message.session_key, B_private_key)

        # Unzipovanje tela+zaglavlja
        if self.algorithms.zip:
            self.message = self.UnZip(self.message)

        # Raspakovanje porukke
        body_header: MessageBodyAndHeader = pickle.loads(self.message)
        self.body = body_header.body

        # Provera potpisa poruke
        return self.Authenticate(self.algorithms.authentificaton, body_header.header)










