import tkinter as tk
from implementation.message2.messagereceiver import MessageReceiver
from implementation.message2.messagesender import MessageSender

import gui.configuration
import gui.util
from implementation.keymanagement.keymanager import KeyManager
import re
from gui.keygen.passwordmodal import PasswordModal
from gui.controller import GuiController
from gui.keygen.keyview import KeyViewGui


class MessageSendReceiveGui(tk.Toplevel):
    pass