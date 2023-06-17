import tkinter as tk

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