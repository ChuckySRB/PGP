import tkinter as tk
import gui.configuration
import gui.util

class KeyGenGui(tk.Tk):
    def __init__(self):
        super().__init__()
        gui.util.init_window(self, "Key generation")
        self._init_name()
        self._init_email()
        self._init_algorithms()
        self._init_key_sizes()


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

        algorithms = ['RSA', 'DSA', 'ElGamal']
        self.algorithm = tk.StringVar()
        self.algorithm.set('RSA')
        optionMenu = tk.OptionMenu(self, self.algorithm, *algorithms)
        optionMenu.grid(column=2, columnspan=2, row=2, padx=5, pady=5)

    def _init_key_sizes(self):
        label_key_size = tk.Label(self ,text="Key size", fg = gui.configuration.LABEL_FG,
                                  background= gui.configuration.BACKGROUND)
        label_key_size.grid(column = 0, columnspan= 2, row = 3, padx = 5, pady = 5)

        key_sizes = ["1024", "2048"]
        self.key_size = tk.StringVar()
        self.key_size.set("1024")
        optionMenu = tk.OptionMenu(self, self.key_size, *key_sizes)
        optionMenu.grid(column = 2, columnspan= 2, row= 3, padx= 5, pady = 5)


#Test for gui
if __name__ == "__main__":

    window_keygen = KeyGenGui()
    window_keygen.mainloop()