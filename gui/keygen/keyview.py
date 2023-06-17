import tkinter as tk
import gui.configuration
import gui.util
from implementation.keymanagement.keymanager import KeyManager
import re
from gui.keygen.passwordmodal import PasswordModal
from gui.controller import GuiController

class KeyViewGui(tk.Toplevel):
    def __init__(self, image_path: str):
        super().__init__()

        gui.util.init_window(self, "Key view", image_path)
        self.added_frame = tk.Frame(self)
        self._init_menu()
        self._init_name()
        self._init_email()
        self._init_button()
        self._init_message_label()
        self._init_scrollbar()
        self.added_frame.grid(column=0, columnspan= 7, row= 3)
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
        # self.message_label = tk.Label(self, text="", fg=gui.configuration.LABEL_FG,
        #                               background=gui.configuration.LABEL_BG)
        # self.message_label.grid(column=0, columnspan=2, row=3, padx=5, pady=5)
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

    def _show_keys(self, name: str, email: str):
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
            self.message_label.config(text = "No keys to display")
        i : int = 0
        for key_to_keys in key_dict:

            # label = tk.Label(self.added_frame, text= "id: " + hex(key_to_keys),  fg=gui.configuration.LABEL_FG,
            #                           background=gui.configuration.LABEL_BG, justify="left", anchor="w")
            # label.pack(anchor="w", padx=5, pady=5)
            # self.added_widgets.append(label)
            self.text.insert(tk.END, "id: " + hex(key_to_keys) + "\n")
            i += 1

            if key_dict[key_to_keys][1] != None:
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
                # label = tk.Label(self.added_frame, text= text_to_display,  fg=gui.configuration.LABEL_FG,
                #                       background=gui.configuration.LABEL_BG, justify="left", anchor="w")
                # label.pack(anchor="w", pady=5, padx=5)
                # label.grid(row= 3 + i, rowspan = 1, columnspan= 6, padx=5, pady= 5)
                # self.added_widgets.append(label)
                # label.grid(row=3 + i, rowspan=1, columnspan= 6, padx=5, pady=5)
                self.text.insert(tk.END, text_to_display)
                i += 1