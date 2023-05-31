import tkinter as tk
import gui.configuration
from PIL import ImageTk, Image

def init_window(window: tk.Tk, title: str):
    window.title(title)
    window.geometry(f"{gui.configuration.WIDTH}x{gui.configuration.HEIGHT}")
    window.geometry(gui.configuration.XYPOS)
    window.configure(bg=gui.configuration.BACKGROUND)
    try:
        image = Image.open("../../asets/neoncity.png")
        image = image.resize((gui.configuration.WIDTH, gui.configuration.HEIGHT), Image.LANCZOS)
        window.background_image = ImageTk.PhotoImage(image)
        canvas = tk.Canvas(window, width=gui.configuration.WIDTH, height=gui.configuration.HEIGHT)
        canvas.create_image(0, 0, anchor=tk.NW, image=window.background_image)
        canvas.place(x=0, y=0)
    except FileNotFoundError:
        print("Image file not found or path is incorrect.")