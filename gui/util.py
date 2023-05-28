import tkinter as tk
import gui.configuration

def init_window(window: tk.Tk, title: str):
    window.title(title)
    window.geometry(f"{gui.configuration.WIDTH}x{gui.configuration.HEIGHT}")
    window.geometry(gui.configuration.XYPOS)
    window.configure(bg=gui.configuration.BACKGROUND)