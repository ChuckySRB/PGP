import tkinter as tk
from PIL import ImageTk, Image

# Funkcija za dugme
def send_msg(label, text):
    label.config(text=text)
def switch_windows():
    window.withdraw()
    window2.deiconify()

# Prozor na kome se pravi sve
window = tk.Tk()
window.title("PGP")
window.geometry("800x800")  # Width x Height
window.geometry("+500+200")  # X position + Y position
window.configure(bg="#e52a30")

image = Image.open("asets/neoncity.png")
image = image.resize((800, 800), Image.ANTIALIAS)  # Resize the image if needed
background_image = ImageTk.PhotoImage(image)
background_label = tk.Label(window, image=background_image)
background_label.place(x=0, y=0, relwidth=1, relheight=1)

window2 = tk.Tk()
window2.geometry("400x300")  # Width x Height
window2.geometry("+500+200")  # X position + Y position
window2.configure(bg="#e52a30")
window2.withdraw()


labeln = tk.Label(window2, text = "Message Sent", fg="white", background="#a30e52")
labeln.grid(row = 0)
# Variable koje se unose
text = tk.Variable()
password = tk.Variable()

# Prvi red - labela obicna
label1 = tk.Label(window, text = "Pretty Good Privacy")
label1.configure(bg="#e52a30", fg="white")
# Nameštanje gde se nalazi
label1.grid(column = 0, row = 0)

# Labela i unos teksta
label2 = tk.Label(window, text = "Ime")
label2.grid(column = 0, row = 1)
ime = tk.Entry(window, textvariable=text)
ime.grid(row=1, column=1, padx=10, pady=5)

# Unos 2
label3 = tk.Label(window, text = "Lozinka")
label3.grid(column = 0, row = 2)
sifra = tk.Entry(window, textvariable= password)
sifra.grid(row=2, column=1, padx=10, pady=5)

# Dugme koje menja labelu i poziva funkciju sa parametrima
button = tk.Button(window, text = "Send", command = lambda: send_msg(label1, password.get()))
button.grid(column = 1, row = 3, padx=10, pady=5)
button2 = tk.Button(window, text = "Next", command = switch_windows)
button2.grid(column = 0, row = 3, padx=10, pady=5)
# Looper - pokreće aplikaciu
window.mainloop()
