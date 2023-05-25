import tkinter as tk

# Funkcija za dugme
def send_msg(label, text):
    label.config(text=text)

# Prozor na kome se pravi sve
window = tk.Tk()
window.title("PGP")

# Variable koje se unose
text = tk.Variable()
password = tk.Variable()

# Prvi red - labela obicna
label1 = tk.Label(window, text = "Pretty Good Privacy")
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

# Looper - pokreće aplikaciu
window.mainloop()
