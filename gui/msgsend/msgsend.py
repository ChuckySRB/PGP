import tkinter as tk
from tkinter import filedialog
import gui.configuration
import gui.util
from implementation.message.messagemanager import *

from PIL import ImageTk, Image

class MessageSend(tk.Tk):
    def __init__(self):
        super().__init__()
        gui.util.init_window(self, "Message Send", "../../asets/neoncity.png")
        self._init_title()
        self._init_message()
        self._init_email()
        self._init_encryption()
        self._init_authentication()
        self._init_compresion()
        self._init_conversion()
        self._init_destination()
        self._init_button()

    def _init_title(self):
        label_title = tk.Label(self, text="Message Sending Window", fg=gui.configuration.LABEL_FG,
                              background=gui.configuration.LABEL_BG)
        label_title.grid(column=2, columnspan=2, row=0, padx=5, pady=5)


    def _init_message(self):
        label_msg = tk.Label(self, text="Message", fg=gui.configuration.LABEL_FG,
                              background=gui.configuration.LABEL_BG)
        label_msg.grid(column=0, columnspan=2, row=1, padx=5, pady=5)

        self.msg = tk.Variable()
        entry_msg = tk.Text(self, width=30, height=20)
        entry_msg.grid(column=0, columnspan=2, rowspan=5, row=2, padx=20, pady=5)

    def _init_email(self):
        label_msg = tk.Label(self, text="E-Mail", fg=gui.configuration.LABEL_FG,
                              background=gui.configuration.LABEL_BG)
        label_msg.grid(column=0, columnspan=1, row=7, padx=5, pady=5)

        self.email = tk.Variable()
        entry_msg = tk.Entry(self, width=40, textvariable=self.email)
        entry_msg.grid(column=1, columnspan=2, row=7, padx=20, pady=5)

    def _init_encryption(self):
        label_encrypt = tk.Label(self, text="Encryption", fg=gui.configuration.LABEL_FG,
                               background=gui.configuration.LABEL_BG)
        label_encrypt.grid(column=2, columnspan=2, row=2, padx=5, pady=5)
        label_public_key = tk.Label(self, text="public key = ", fg=gui.configuration.LABEL_FG,
                                 background=gui.configuration.LABEL_BG)
        label_public_key.grid(column=6, row=2, padx=5, pady=5)
        public_keys = [1, 2, 3]
        self.public_key = tk.IntVar()
        self.public_key.set(1)
        optionMenu3 = tk.OptionMenu(self, self.public_key, *public_keys)
        optionMenu3.grid(column=7, columnspan=2, row=2, padx=5, pady=5)

        algorithms = ['No Encryption', 'TripleDES', 'AES128']
        self.algorithm = tk.StringVar()
        self.algorithm.set('No Encryption')
        optionMenu = tk.OptionMenu(self, self.algorithm, *algorithms)
        optionMenu.grid(column=4, columnspan=2, row=2, padx=5, pady=5)
    def _init_authentication(self):
        label_auth = tk.Label(self, text="Authentication", fg=gui.configuration.LABEL_FG,
                                   background=gui.configuration.LABEL_BG)
        label_auth.grid(column=2, columnspan=2, row=3, padx=5, pady=5)

        self.auth = tk.Variable()
        self.auth.set(False)

        auth_check = tk.Checkbutton(self, text = "SHA-1", variable = self.auth)
        auth_check.grid(column=6, columnspan=2, row=3, padx=5, pady=5)

        private_keys = [1, 2, 3]
        self.private_key = tk.IntVar()
        self.private_key.set(1)
        optionMenu2 = tk.OptionMenu(self, self.private_key, *private_keys)
        optionMenu2.grid(column=4, columnspan=2, row=3, padx=5, pady=5)
    def _init_compresion(self):
        label_zip = tk.Label(self, text="Compresion", fg=gui.configuration.LABEL_FG,
                              background=gui.configuration.LABEL_BG)
        label_zip.grid(column=2, columnspan=2, row=4, padx=5, pady=5)

        self.zip = tk.Variable()
        self.zip.set(False)

        zip_check = tk.Checkbutton(self, text="ZIP", variable=self.zip)
        zip_check.grid(column=4, columnspan=2, row=4, padx=5, pady=5)
    def _init_conversion(self):
        label_radix = tk.Label(self, text="Conversion", fg=gui.configuration.LABEL_FG,
                              background=gui.configuration.LABEL_BG)
        label_radix.grid(column=2, columnspan=2, row=5, padx=5, pady=5)

        self.radix = tk.Variable()
        self.radix.set(False)

        radix_check = tk.Checkbutton(self, text="Radix-64", variable=self.radix)
        radix_check.grid(column=4, columnspan=2, row=5, padx=5, pady=5)

    def _choose_folder(self):
        folder_path = filedialog.askdirectory()
        self.destination_folder_entry.delete(0, tk.END)
        self.destination_folder_entry.insert(tk.END, folder_path)

    def _init_destination(self):
        label_dest = tk.Label(self, text="Destination", fg=gui.configuration.LABEL_FG,
                             background=gui.configuration.LABEL_BG)
        label_dest.grid(column=2, columnspan=2, row=6, padx=5, pady=5)
        self.path = tk.Variable()
        self.destination_folder_entry = tk.Entry(self, width=40, textvariable=self.path)
        self.destination_folder_entry.grid(column=4, columnspan=2, row=6, padx=5, pady=5)

        # Button to open file dialog and choose destination folder
        choose_folder_button = tk.Button(self, text="Choose Folder", command=self._choose_folder)
        choose_folder_button.grid(column=6, columnspan=2, row=6, padx=5, pady=5)


    def _init_button(self):
        send_msg = tk.Button(self, text = "Send Message", command= lambda : MessageManager.send(self.path.get(),
                                                                                                      self.email.get(), self.private_key,
                                                                                                      self.public_key, self.auth, self.algorithm,
                                                                                                      self.zip, self.radix))
        send_msg.grid(column=6, columnspan=2, row=10, padx=5, pady=5)

# Test for gui
if __name__ == "__main__":
    window = MessageSend()
    window.mainloop()
