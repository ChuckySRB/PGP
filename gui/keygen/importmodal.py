import tkinter as tk
from implementation.keymanagement.keywrapper.keywrapper import KeyWrapper, IncorrectKeyPassword
from tkinter import filedialog
from implementation.keymanagement.keymanager import KeyManager

class ImportModal(tk.Toplevel):

    def __init__(self, key_view_window: tk.Toplevel, email: str, key_manager: KeyManager):

        super().__init__(key_view_window)
        self.email: str = email
        self.key_manager: KeyManager = key_manager
        self.title("Import key")
        self.geometry("500x500")
        self.config(bg="white")

        self.password = tk.Variable()
        password_label = tk.Label(self, text = "Enter password for private key (if public no need)")
        password_label.grid(column = 0, columnspan= 3, row = 0, padx = 5, pady = 5)
        entry_password = tk.Entry(self, show="*", textvariable=self.password)
        entry_password.grid(column= 3, columnspan= 2, row = 0, padx= 5, pady = 5)


        self.file_path = tk.Variable()
        entry_explorer = tk.Entry(self, textvariable= self.file_path, width= 60)
        entry_explorer.grid(column= 0, columnspan= 4, row = 1, padx = 5, pady = 5)
        button_browse = tk.Button(self, text= "Browse files", command = lambda: self._browse_files())
        button_browse.grid(column = 4, columnspan= 2, row = 1, padx = 5, pady = 5)

        import_button = tk.Button(self, text = "Import", command = lambda : self._import())
        import_button.grid(column= 0, columnspan= 2, row = 2, padx= 5, pady= 5)

        self.message_label = tk.Label(self, text= "")
        self.message_label.grid(column= 0, columnspan= 2, row = 3, padx= 5, pady = 5)

    def _browse_files(self):
        file = filedialog.askopenfilename(
            initialdir=".",
            title = "Select a file",
            filetypes= (("PEM files", "*.pem"), ("all_files", "*.*"))
        )

        self.file_path.set(file)


    def _import(self):
        try:
            key_wrapper: KeyWrapper = None
            email, algorithm,key_size, key_wrapper = KeyWrapper.import_key(self.file_path.get(), self.password.get())
            id: int = key_wrapper.get_parameters(self.password.get())["id"]

            if id not in self.key_manager.key_dict:
                self.key_manager.key_dict[id] = [None, None]

            if key_wrapper.is_private():
                self.key_manager.key_dict[id][0] = key_wrapper
            else:
                self.key_manager.key_dict[id][1] = key_wrapper

            self.message_label.config(text="Successfully imported key!")

        except IncorrectKeyPassword:
            self.message_label.config(text= "Incorrect key password!")
        except FileNotFoundError:
            self.message_label.config(text="File not found!")
        except PermissionError:
            self.message_label.config(text="No permission!")