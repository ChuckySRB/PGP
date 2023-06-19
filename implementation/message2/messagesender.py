from implementation.keymanagement.keymanager import  KeyManager
from implementation.keymanagement.keywrapper.keywrapper import KeyWrapper

from cryptography.hazmat.primitives.ciphers import Cipher
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import base64
import zipfile
import time
from io import BytesIO
import shutil
import os
from messagereceiver import MessageReceiver

class MessageSender:

    def __init__(self):
        pass

    def send_message(self, msg: bytes, file_path: str, sender: str, receiver: str, signature_key: KeyWrapper = None, signature_key_password: str = None, encryption_algorithm: str = None, encryption_key: KeyWrapper = None, zip: bool = False, radix64: bool = False):

        timestamp: bytes = str(time.time()).encode('utf-8')
        msg = b'Message:\n' + timestamp + b'\n' + msg
        print(msg)

        if signature_key != None:

            signature: bytes = signature_key.sign(msg, signature_key_password)
            leading_octets: bytes = signature[0:2]
            key_id: bytes = signature_key.get_parameters(signature_key_password)["id"].to_bytes(8, "big")
            timestamp_signature: bytes = str(time.time()).encode('utf-8')
            signature_header: bytes = b'Signature:\n' + timestamp_signature + b'\n' + sender.encode("utf-8") + b'\n' + key_id + leading_octets + signature + b'\n'

            msg = signature_header + msg
            print(f'Signed msg: {msg}')

        if zip:
            bytesIO: BytesIO = BytesIO()
            with zipfile.ZipFile(bytesIO, 'w') as zip_archive:
                zipped_msg: zipfile.ZipInfo = zipfile.ZipInfo('message.txt')
                zip_archive.writestr(zipped_msg, msg, compress_type= zipfile.ZIP_DEFLATED)

            msg = b'Zipped:\n' + bytesIO.getvalue()
            print(f'Zipped msg: {msg}')

        if encryption_key != None and encryption_algorithm != None:
            encryption_header: bytes = b'Encryption:\n'
            encrypted_session_key: bytes = b''
            cipher : Cipher = None
            session_key: bytes = os.urandom(16)
            if encryption_algorithm == "AES":
                # iv = b'0' * 16
                cipher = Cipher(algorithms.AES(session_key), modes.ECB())


            elif encryption_algorithm == "DES":
                # iv = b'0' * 16
                cipher = Cipher(algorithms.TripleDES(session_key), modes.ECB())

            encryptor = cipher.encryptor()
            ct : bytes = b''
            pad_length: int = 0
            if len(msg) % 16 != 0:
                pad_length = 16 - (len(msg) % 16)
                msg += b'\0' * pad_length
            ct = encryptor.update(msg) + encryptor.finalize()

            encrypted_session_key: bytes = encryption_key.encrypt(session_key)

            msg =  encryption_header + receiver.encode('utf-8') + b'\n' + encryption_key.get_parameters()["id"].to_bytes(8, "big") + encrypted_session_key + encryption_algorithm.encode('utf-8') + b'\n' + pad_length.to_bytes(1, "big") + ct
            print(msg)

        if radix64:
            radix64_header: bytes = b'Radix:\n'
            msg = base64.b64encode(msg)
            msg = radix64_header + msg
            print(msg)

        with open(file_path, "wb") as file:
            file.write(msg)


if __name__ == "__main__":

    msg_sender: MessageSender = MessageSender()
    msg_receiver: MessageReceiver = MessageReceiver()

    key_manager = KeyManager.get_key_manager("j", "j")[0]
    key_manager.gen_keys(1024, "RSA", "j")

    key_manager.get_keys()
    for id in key_manager.get_keys():
        msg_sender.send_message(b'Hello there222313', "path", "j", "j",
                                signature_key= key_manager.key_dict[id][0],
                                signature_key_password= "j",
                                zip= True,
                                encryption_algorithm= "AES",
                                encryption_key= key_manager.key_dict[id][1],
                                radix64= True
                                )

        msg_receiver.receive_message("path", key_manager)


