import tkinter as tk
from implementation.keymanagement.keywrapper.keywrapper import KeyWrapper, IncorrectKeyPassword
from tkinter import filedialog

class ExportModal(tk.Toplevel):

    def __init__(self, key_view_window: tk.Toplevel, key_wrapper: KeyWrapper, email: str):
        super().__init__(key_view_window)

        self.key_wrapper = key_wrapper
        self.email: str = email
        self.title("Export key")
        self.geometry("500x500")
        self.config(bg="white")

        self.password = tk.Variable()
        if self.key_wrapper.is_private():
            label = tk.Label(self, text = "Enter password for private key")
            label.grid(column = 0, columnspan= 2, row = 0, padx = 5, pady = 5)

            entry_password = tk.Entry(self, show = "*", textvariable=self.password)
            entry_password.grid(column = 2, columnspan= 2, row = 0, padx= 5, pady= 5)

        self.file_path = tk.Variable()
        entry_explorer = tk.Entry(self, textvariable = self.file_path, width= 60)
        entry_explorer.grid(column = 0, columnspan= 4, row = 1, padx = 5, pady = 5)
        button_browse = tk.Button(self, text = "Browse folder", command = lambda: self._browse_directories())
        button_browse.grid(column = 4, columnspan= 2, row = 1, padx = 5, pady = 5)

        export_button = tk.Button(self, text="Export", command= lambda: self._export())
        export_button.grid(column= 0, columnspan= 2, row = 2, padx= 5, pady= 5)

        self.message_label = tk.Label(self, text="")
        self.message_label.grid(column = 0, columnspan= 2, row = 3, padx = 5, pady = 5)

    def _browse_directories(self):
        directory = filedialog.askdirectory(
            initialdir = ".",
            title = "Select a folder",
        )

        self.file_path.set(directory + "/")

    def _export(self):
        try:
            self.key_wrapper.export_key(self.file_path.get(), self.email, self.password.get())
            self.message_label.config(text="Succesfully exported!")
        except PermissionError:
            self.message_label.config(text="Permission denied to open file!")
        except FileNotFoundError:
            self.message_label.config(text="File not found!")
        except IncorrectKeyPassword:
            self.message_label.config(text="Incorrect key password")