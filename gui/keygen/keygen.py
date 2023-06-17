import tkinter as tk
import gui.configuration
import gui.util
from implementation.keymanagement.keymanager import KeyManager
import re

class KeyGenGui(tk.Tk):
    def __init__(self, image_path: str):
        super().__init__()
        gui.util.init_window(self, "Key generation", image_path)
        self._init_name()
        self._init_email()
        self._init_algorithms()
        self._init_key_sizes()
        self._init_button()
        self._init_message_label()


    def _init_name(self):
        label_name = tk.Label(self, text="Name", fg=gui.configuration.LABEL_FG,
                              background=gui.configuration.LABEL_BG)
        label_name.grid(column=0, columnspan=2, row=0, padx=5, pady=5)

        self.name = tk.Variable()
        entry_name = tk.Entry(self, textvariable=self.name)
        entry_name.grid(column=2, columnspan=2, row=0, padx=5, pady=5)

    def _init_email(self):
        label_email = tk.Label(self, text="Email", fg=gui.configuration.LABEL_FG,
                               background=gui.configuration.LABEL_BG)
        label_email.grid(column=0, columnspan=2, row=1, padx=5, pady=5)

        self.email = tk.Variable()
        entry_email = tk.Entry(self, textvariable=self.email)
        entry_email.grid(column=2, columnspan=2, row=1, padx=5, pady=5)

    def _init_algorithms(self):
        label_algorithm = tk.Label(self, text="Algorithm", fg=gui.configuration.LABEL_FG,
                                   background=gui.configuration.LABEL_BG)
        label_algorithm.grid(column = 0, columnspan = 2, row = 2, padx = 5, pady = 5)

        algorithms = ['RSA', 'DSA', 'Elgamal']
        self.algorithm = tk.StringVar()
        self.algorithm.set('RSA')
        optionMenu = tk.OptionMenu(self, self.algorithm, *algorithms)
        optionMenu.grid(column=2, columnspan=2, row=2, padx=5, pady=5)

    def _init_key_sizes(self):
        label_key_size = tk.Label(self ,text="Key size", fg = gui.configuration.LABEL_FG,
                                  background= gui.configuration.LABEL_BG)
        label_key_size.grid(column = 0, columnspan= 2, row = 3, padx = 5, pady = 5)

        key_sizes = ["1024", "2048"]
        self.key_size = tk.StringVar()
        self.key_size.set("1024")
        optionMenu = tk.OptionMenu(self, self.key_size, *key_sizes)
        optionMenu.grid(column = 2, columnspan= 2, row= 3, padx= 5, pady = 5)

    def _init_button(self):
        button_keygen = tk.Button(self, text= "Generate keys", command= lambda: self._generate_keys(
            self.name.get(),
            self.email.get(),
            self.algorithm.get(),
            int(self.key_size.get())
        ))
        button_keygen.grid(column= 0, columnspan= 4, row = 4, padx = 5, pady = 5)

    def _init_message_label(self):
        self.message_label = tk.Label(self, text="", fg = gui.configuration.LABEL_FG,
                                  background= gui.configuration.LABEL_BG)
        self.message_label.grid(column = 0, columnspan= 2, row = 5, padx = 5, pady = 5)

    def _generate_keys(self, name: str, email: str, algorithm: str, key_size: int):
        message: str = "You didn't generate keys!"
        if re.search(".+@.+", email) is None:
            message: str = "Email not valid"
            self.message_label.config(text=message)
            return
        if len(name) == 0:
            message: str = "No 0-length names allowed"
            self.message_label.config(text=message)
            return

        self.password = ""
        key_manager_or_None = KeyManager.get_key_manager(name, email)
        if(key_manager_or_None[0] is None):
            message = key_manager_or_None[1]
        else:
            key_manager: KeyManager = key_manager_or_None[0]
            key_gen_password_modal = PasswordModal(self)
            self.wait_window(key_gen_password_modal)

            if(self.password != ""):
                message = "You generated keys!"
                key_manager.gen_keys(key_size, algorithm, self.password)


        self.message_label.config(text=message)

class PasswordModal(tk.Toplevel):

    def __init__(self, key_gen_window):
        super().__init__(key_gen_window)
        self.toplevel = key_gen_window
        self.title("Password")
        self.geometry("300x150")
        self.config(bg="white")
        label = tk.Label(self, text = "Enter password for private key")
        label.grid(column = 0, columnspan= 2, row = 0, padx = 5, pady = 5)

        self.password = tk.Variable()
        entry_password = tk.Entry(self, show = "*", textvariable=self.password)
        entry_password.grid(column = 0, columnspan= 2, row = 1, padx= 5, pady= 5)

        submit_button = tk.Button(self, text="Submit", command= lambda: self.submit_password())
        submit_button.grid(column= 0, columnspan= 2, row = 2, padx= 5, pady= 5)

    def submit_password(self):
        self.toplevel.password = self.password.get()
        self.destroy()

#Test for gui
if __name__ == "__main__":

    window_keygen = KeyGenGui("../../asets/neoncity.png")
    window_keygen.mainloop()