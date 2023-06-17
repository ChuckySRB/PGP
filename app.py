import tkinter as tk
from PIL import ImageTk, Image


HEIGHT = 600 #prevelik mi je za laps 800
WIDTH = 800
if __name__ == "__main__":

    # Prozor na kome se pravi sve
    window = tk.Tk()
    window.title("PGP")
    window.geometry(str(WIDTH) + "x" + str(HEIGHT))  # Width x Height
    window.geometry("+500+200")  # X position + Y position
    window.configure(bg="#e52a30")

    image = Image.open("asets/neoncity.png")
    image = image.resize((WIDTH, HEIGHT), Image.ANTIALIAS)  # Resize the image if needed
    background_image = ImageTk.PhotoImage(image)
    background_label = tk.Label(window, image=background_image)
    background_label.place(x=0, y=0, relwidth=1, relheight=1)

    button_keygen = tk.Button(window, text="Generate keys", command= lambda: print("Hello!"))
    button_keygen.grid(column=0, columnspan=2, row= 0, padx = 5, pady = 5)
    # Looper - pokreće aplikaciu
    window.mainloop()
