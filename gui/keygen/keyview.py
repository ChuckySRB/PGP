import tkinter as tk
import gui.configuration
import gui.util
from implementation.keymanagement.keymanager import KeyManager
import re
from gui.keygen.passwordmodal import PasswordModal, PrivateKeyShowModal
from gui.keygen.exportmodal import ExportModal
from gui.controller import GuiController
from implementation.keymanagement.keywrapper.keywrapper import  KeyWrapper

class KeyViewGui(tk.Toplevel):
    def __init__(self, image_path: str):
        super().__init__()

        gui.util.init_window(self, "Key view", image_path)
        self.added_frame = tk.Frame(self)
        self._init_menu()
        self._init_name()
        self._init_email()
        self._init_button()
        self._init_import_button()
        self._init_message_label()
        self._init_scrollbar()
        self.added_frame.grid(column=0, columnspan= 7, row= 4)
        self.added_widgets = []

    def _init_menu(self):
        menubar = tk.Menu(self)
        self.config(menu=menubar)

        menubar.add_command(
            label = "Key Generate",
            command = lambda: self._switch_window()
        )

    def _switch_window(self):
        # self.message_label.config(text="")
        self.text.delete("1.0", "end")
        for widget in self.added_widgets:
            widget.destroy()
        self.added_widgets = []
        GuiController.switch_window("keygen")

    def reset(self):
        pass

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

    def _init_message_label(self):
        pass

    def _init_scrollbar(self):

        scrollbar = tk.Scrollbar(self.added_frame, orient="vertical")
        scrollbar.pack(side=tk.RIGHT, fill="y")
        self.text = tk.Text(self.added_frame, yscrollcommand=scrollbar.set, width=70)

        self.text.pack(anchor="w",padx=5, pady=5)
        scrollbar.config(command=self.text.yview)

    def _init_button(self):
        button_show = tk.Button(self, text= "Show keys", command= lambda: self._show_keys(self.name.get(), self.email.get()))
        button_show.grid(column= 0, columnspan= 2, row = 2, padx = 5, pady = 5)

    def _init_import_button(self):
        button_import = tk.Button(self, text= "Import key", command= lambda: print("Hello"))
        button_import.grid(column= 0, columnspan= 2, row = 3, padx = 5, pady = 5)

    def _show_keys(self, name: str, email: str):
        self.text.delete("1.0", "end")
        if re.search(".+@.+", email) is None:
            message: str = "Email not valid"
            self.text.insert(tk.END, message)
            return
        if len(name) == 0:
            message: str = "No 0-length names allowed"
            self.text.insert(tk.END, message)
            return

        key_manager_or_None = KeyManager.get_key_manager(name, email)

        if key_manager_or_None[0] is None:
            self.text.insert(tk.END, key_manager_or_None[1])
            return
        key_manager: KeyManager = key_manager_or_None[0]

        key_dict: dict = key_manager.get_keys()
        if len(key_dict.keys()) == 0:
            self.text.insert(tk.END, "No keys to display")
        for key_to_keys in key_dict:
            self.text.insert(tk.END, "id: " + hex(key_to_keys) + "\n")

            if key_dict[key_to_keys][1] != None:
                self.text.insert(tk.END, "\t" + key_dict[key_to_keys][1].get_algorithm() + "\n")
                text_to_display: str = "\tpub_key:\n"
                param_dict: dict = key_dict[key_to_keys][1].get_parameters()
                for param_key in param_dict:
                    num: str = hex(param_dict[param_key])
                    temp_text:str = f"\t\t{param_key}: "
                    j = 0
                    while j < len(num):
                        boundary: int =  \
                            j + 50 - len(temp_text) if j + 50 - len(temp_text) < len(num) else len(num)
                        temp_text += num[j: boundary] + "\n"
                        j = boundary
                        text_to_display += temp_text
                        temp_text = "\t\t"

                self.text.insert(tk.END, text_to_display)
                self.text.insert(tk.END, "\n\t\t")
                self.text.window_create(self.text.index("end"), window = tk.Button(self.text, text = "Export public key", command = lambda: self._export_key(key_dict[key_to_keys][1], email)))
                self.text.insert(tk.END, "\n")
            else:
                self.text.insert(tk.END, "\t\tPublic key not yet imported\n")

            if key_dict[key_to_keys][0] != None:
                self.text.insert(tk.END, "\t\t")
                self.text.window_create(self.text.index("end"), window = tk.Button(self.text, text = "See private key", command= lambda: self._see_private_key(key_dict[key_to_keys][0])))
                self.text.insert(tk.END, "\t")
                self.text.window_create(self.text.index("end"), window = tk.Button(self.text, text = "Export private key", command = lambda: self._export_key(key_dict[key_to_keys][0], email)))
                self.text.insert(tk.END, "\n")
            else:
                self.text.insert(tk.END, "\t\tPrivate key not yet imported\n")

    def _see_private_key(self, private_key_wrapper: KeyWrapper):
        show_private_key_modal: PrivateKeyShowModal = PrivateKeyShowModal(self, private_key_wrapper)
        self.wait_window(show_private_key_modal)

    def _export_key(self, public_key_wrapper: KeyWrapper, email: str):
        export_modal: ExportModal = ExportModal(self, public_key_wrapper, email)
        self.wait_window(export_modal)
