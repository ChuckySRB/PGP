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
import tkinter as tk

class MessageReceiver:

    def __init__(self):
        pass

    def receive_message(self, file_path: str, key_manager: KeyManager, top: tk.Toplevel = None) -> bytes:
        msg: bytes = b''
        with open(file_path, "rb") as file:
            msg = file.read()

        radix_header: bytes = b'Radix:\n'
        if radix_header in msg:
            msg = msg[len(radix_header):]
            msg = base64.b64decode(msg)
            print(msg)

        encryption_header: bytes = b'Encryption:\n'
        if encryption_header in msg:
            msg = msg[len(encryption_header):]
            aes_header: bytes = b"AES\n"
            des_header: bytes = b"DES\n"

            cipher: Cipher = None

            ind:int = msg.find(b'\n')
            receiver: bytes = msg[0:ind]
            # print(receiver)
            msg = msg[ind + 1:]

            if receiver != key_manager.email.encode("utf-8"):
                return b''

            encryption_key_id: int = int.from_bytes(msg[0: 8], 'big')
            if encryption_key_id not in key_manager.key_dict:
                return b''

            encryption_key: KeyWrapper = key_manager.key_dict[encryption_key_id][0]
            if encryption_key is None:
                return b''

            msg = msg[8:]
            # print(msg)
            encrypted_session_key: bytes = msg[0:encryption_key.size // 8]
            msg = msg[encryption_key.size // 8:]

            session_key: bytes = encryption_key.decrypt(encrypted_session_key, "j")[0:16]

            if aes_header in msg:
                cipher = Cipher(algorithms.AES(session_key), modes.ECB())
                msg = msg[len(aes_header):]
            elif des_header in msg:
                cipher = Cipher(algorithms.TripleDES(session_key), modes.ECB())
                msg = msg[len(des_header):]

            pad_length: int = msg[0]
            msg = msg[1:]
            decryptor = cipher.decryptor()

            msg = decryptor.update(msg) + decryptor.finalize()
            if pad_length != 0:
                msg = msg[:-pad_length]
            print(msg)

        zip_header: bytes = b'Zipped:\n'
        if zip_header in msg:
            msg = msg[len(zip_header):]
            bytesIO: BytesIO = BytesIO(msg)

            with zipfile.ZipFile(bytesIO, 'r') as zip_archive:
                # zipped_msg: zipfile.ZipInfo = zipfile.ZipInfo('message.txt')
                msg = zip_archive.read('message.txt')

            print(msg)

        signature_header: bytes = b'Signature:\n'
        verification_key: KeyWrapper = None
        if signature_header in msg:
            msg = msg[len(signature_header):]
            ind: int = msg.find(b'\n')
            msg = msg[ind + 1 :]
            ind: int = msg.find(b'\n')

            sender: bytes = msg[:ind]
            msg = msg[ind + 1:]

            if sender.decode('utf-8') not in KeyManager.KEY_MANAGER_DICT:
                return b''

            verification_key = KeyManager.KEY_MANAGER_DICT[sender.decode('utf-8')].key_dict[int.from_bytes(msg[0:8], "big")][1]
            if verification_key is None:

                return b''
            msg = msg[8:]
            msg = msg[2:]

            signature: bytes = msg[:verification_key.size // 8]
            msg = msg[verification_key.size // 8 + 1:]

            print(signature)
            if verification_key.verify(msg, signature):
                print(msg)
                return msg
            else:
                return b''

        print(msg)


        return msg


