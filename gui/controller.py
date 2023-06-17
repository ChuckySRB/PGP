import tkinter as tk
# from gui.keygen.keygen import KeyGenGui
# from gui.keygen.keyview import  KeyViewGui
class UnexistingWindow:
    """Exception thrown on unexisting window"""

class GuiController:


    WINDOWS: dict = {}
    CURRENTLY_RUNNING: tk.Tk = None

    @staticmethod
    def switch_window(window_name: str):
        GuiController.CURRENTLY_RUNNING.withdraw()
        GuiController.CURRENTLY_RUNNING = GuiController.WINDOWS[window_name]
        GuiController.CURRENTLY_RUNNING.deiconify()

    @staticmethod
    def add_window(window_name: str, window: tk.Tk):
        GuiController.WINDOWS[window_name] = window


if __name__ == "__main__":
    pass
    # GuiController.WINDOWS["keygen"] = KeyGenGui("../asets/neoncity.png")
    # GuiController.WINDOWS["keyview"] = KeyViewGui("../asets/neoncity.png")
    # GuiController.CURRENTLY_RUNNING = GuiController.WINDOWS["keygen"]
    # for window in GuiController.WINDOWS.values():
    #     if window != GuiController.CURRENTLY_RUNNING:
    #         window.withdraw()
    #
    # GuiController.CURRENTLY_RUNNING.mainloop()


