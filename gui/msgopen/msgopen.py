import tkinter as tk
from tkinter import filedialog
import gui.configuration
import gui.util
from implementation.message.messagemanager import *

from PIL import ImageTk, Image

class MessageRead(tk.Tk):
    def __init__(self, email, password):
        super().__init__()
        gui.util.init_window(self, "Message Send", "../../asets/neoncity.png")
        self.user = email
        self.password = password
        self.message = "Message to be displayed!"
        self._init_title()
        self._init_message()
        self._init_message_file()
        self._init_button()


    def _init_title(self):
        label_title = tk.Label(self, text="Message Reader Window", fg=gui.configuration.LABEL_FG,
                              background=gui.configuration.LABEL_BG)
        label_title.grid(column=1, columnspan=2, row=0, padx=5, pady=5)


    def _init_message(self):
        self.text_box = tk.Text(self, width=50, height=20)
        self.text_box.grid(column=0, columnspan=4, row=6, padx=5, pady=5)

        # Insert the message into the Text widget
        self.text_box.insert(tk.END, self.message)

        # Allow scrolling
        scrollbar = tk.Scrollbar(self, command=self.text_box.yview)
        self.text_box.config(yscrollcommand=scrollbar.set)


    def _choose_file(self):
        file_path = filedialog.askopenfilename()
        self.file_entry.delete(0, tk.END)
        self.file_entry.insert(tk.END, file_path)

    def _init_message_file(self):
        label_dest = tk.Label(self, text="Message File Path", fg=gui.configuration.LABEL_FG,
                             background=gui.configuration.LABEL_BG)
        label_dest.grid(column=1, columnspan=2, row=1, padx=5, pady=5)
        self.path = tk.Variable()
        self.file_entry = tk.Entry(self, width=40, textvariable=self.path)
        self.file_entry.grid(column=1, columnspan=2, row=2, padx=5, pady=5)

        # Button to open file dialog and choose destination folder
        choose_folder_button = tk.Button(self, text="Choose File", command=self._choose_file)
        choose_folder_button.grid(column=3, columnspan=1, row=2, padx=5, pady=5)

    def read_message(self):
        self.message = MessageManager.read(self.user, self.password, self.path.get())
        self.text_box.insert(tk.END, self.message)


    def _init_button(self):
        label_user = tk.Label(self, text=f"Loged In as: {self.user}", fg=gui.configuration.LABEL_FG,
                              background=gui.configuration.LABEL_BG)
        label_user.grid(column=1, columnspan=2, row=4, padx=5, pady=5)
        send_msg = tk.Button(self, text = "Read Message",
                             command= lambda : self.read_message())
        send_msg.grid(column=1, columnspan=1, row=5, padx=5, pady=5)

# Test for gui
if __name__ == "__main__":
    km, msg = KeyManager.get_key_manager("mika", "mika@gmail.com")
    km2, msg2 = KeyManager.get_key_manager("zika", "zika@gmail.com")
    km3, msg3 = KeyManager.get_key_manager("pera", "p")
    km4, msg4 = KeyManager.get_key_manager("koja", "k")
    km.gen_keys(2048, "RSA", "123")
    km2.gen_keys(2048, "RSA", "123")
    km3.gen_keys(2048, "DSA", "123")
    km4.gen_keys(2048, "DSA", "123")
    km.gen_keys(1024, "Elgamal", "123")
    km2.gen_keys(1024, "Elgamal", "123")
    km3.gen_keys(1024, "Elgamal", "123")
    km4.gen_keys(1024, "Elgamal", "123")
    window = MessageRead("zika@gmail.com", "123")
    window.mainloop()
