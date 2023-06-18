import tkinter as tk
from implementation.keymanagement.keywrapper.keywrapper import KeyWrapper, IncorrectKeyPassword

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

class PrivateKeyShowModal(tk.Toplevel):

    def __init__(self, key_view_window: tk.Toplevel, private_key_wrapper: KeyWrapper):
        super().__init__(key_view_window)
        self.private_key_wrapper: KeyWrapper = private_key_wrapper
        self.title("Private Key Show")
        self.geometry("500x500")
        self.config(bg="white")



        label = tk.Label(self, text = "Enter password for private key")
        label.grid(column = 0, columnspan= 2, row = 0, padx = 5, pady = 5)

        self.password = tk.Variable()
        entry_password = tk.Entry(self, show = "*", textvariable=self.password)
        entry_password.grid(column = 0, columnspan= 2, row = 1, padx= 5, pady= 5)

        submit_button = tk.Button(self, text="Submit", command= lambda: self.submit_password())
        submit_button.grid(column= 0, columnspan= 2, row = 2, padx= 5, pady= 5)

        finish_button = tk.Button(self, text="Finish", command= lambda: self.finish())
        finish_button.grid(column= 3, columnspan=2, row= 2, padx= 5, pady= 5)

        self.show_frame = tk.Frame(self)
        self.show_frame.grid(column= 0, columnspan=6, row= 3, padx=5, pady=5)
        scrollbar = tk.Scrollbar(self.show_frame, orient="vertical")
        scrollbar.pack(side=tk.RIGHT, fill="y")

        self.text = tk.Text(self.show_frame, yscrollcommand=scrollbar.set, width=50)
        self.text.pack(anchor="w",padx=5, pady=5)

    def finish(self):
        self.destroy()
    def submit_password(self):
        self.text.delete("1.0", "end")
        password_str = self.password.get()
        try:
            text_to_display: str = ""
            parameter_dict: dict = self.private_key_wrapper.get_parameters(password_str)
            for param_key in parameter_dict:
                num: str = hex(parameter_dict[param_key])
                temp_text: str = f"\t{param_key}: "
                j = 0
                while j < len(num):
                    boundary: int = \
                        j + 40 - len(temp_text) if j + 40 - len(temp_text) < len(num) else len(num)
                    temp_text += num[j: boundary] + "\n"
                    j = boundary
                    text_to_display += temp_text
                    temp_text = "\t"

            self.text.insert(tk.END, text_to_display)
        except IncorrectKeyPassword:
            self.text.insert(tk.END, "Incorrect key password")
