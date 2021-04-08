# import tkinter module
from tkinter import *

# import other necessery modules
import random

# Vigenère cipher for encryption and decryption
import base64

# creating root object
root = Tk()

# defining size of window
root.geometry("1200x300")
root.configure(bg='#191c2f')
# setting up the title of window
root.title("Message Encryption and Decryption")

Tops = Frame(root, width=1600,bg='#191c2f', relief=SUNKEN)
Tops.pack(side=TOP)

f1 = Frame(root, width=800,bg="#191c2f", relief=SUNKEN)

f1.pack(side=TOP)

# ==============================================


lblInfo = Label(Tops,bg='#191c2f', font=('helvetica', 25, 'bold'),
                text="SECRET MESSAGING ",
                fg="white", bd=10, anchor='w')

lblInfo.grid(row=0, column=0)


# Initializing variables
Msg = StringVar()
key = StringVar()
mode = StringVar()
Result = StringVar()


# labels for the message
lblMsg = Label(f1,fg="white",bg='#191c2f', font=('Gilroy',16,'bold'),
               text="MESSAGE :",justify='right', bd=16, anchor="w")

lblMsg.grid(row=1, column=0)
# Entry box for the message
txtMsg = Entry(f1, font=('Gilroy',16,'bold'),
               textvariable=Msg, bd=1, insertwidth=4,
               bg="white", justify='right')


txtMsg.grid(row=1, column=1)
# labels for the key
lblkey = Label(f1,fg="white",bg='#191c2f', font=('Gilroy',16,'bold'),
               text="KEY (Only Integer) :", bd=16, anchor="w")

lblkey.grid(row=2, column=0)


# Entry box for the key
txtkey = Entry(f1, font=('Gilroy',16,'bold'),
               textvariable=key, bd=1, insertwidth=4,
               bg="white", justify='right')

txtkey.grid(row=2, column=1)

# labels for the mode
lblmode = Label(f1,bg='#191c2f',fg="white", font=('Gilroy',16,'bold'),
                text="MODE(e for encrypt, d for decrypt) :",
                bd=16, anchor="w")

lblmode.grid(row=3, column=0)
# Entry box for the mode
txtmode = Entry(f1, font=('Gilroy',16,'bold'),
                textvariable=mode, bd=1, insertwidth=4,
                bg="white", justify='right')

txtmode.grid(row=3, column=1)

# labels for the result
lblResult = Label(f1,bg='#191c2f',fg="white", font=('Gilroy',16,'bold'),
                  text="The Result :", bd=16, anchor="w")

lblResult.grid(row=2, column=2)

# Entry box for the result
txtResult = Entry(f1, font=('Gilroy',16,'bold'),
                  textvariable=Result, bd=1, insertwidth=4,
                  bg="white", justify='right')

txtResult.grid(row=2, column=3)

# Vigenère cipher

# Function to encode


def encode(key, msg):
    enc = []
    for i in range(len(msg)):
        key_c = key[i % len(key)]
        enc_c = chr((ord(msg[i]) +
                     ord(key_c)) % 256)
        enc.append(enc_c)
        print("enc:", enc)
    return base64.urlsafe_b64encode("".join(enc).encode()).decode()

# Function to decode


def decode(key, enc):
    dec = []

    enc = base64.urlsafe_b64decode(enc).decode()
    for i in range(len(enc)):
        key_c = key[i % len(key)]
        dec_c = chr((256 + ord(enc[i]) -
                     ord(key_c)) % 256)

        dec.append(dec_c)
        print("dec:", dec)
    return "".join(dec)


def Results():
    # print("Message= ", (Msg.get()))

    msg = Msg.get()
    k = key.get()
    m = mode.get()

    if (m == 'e'):
        Result.set(encode(k, msg))
    else:
        Result.set(decode(k, msg))

# exit function

def qExit():
    root.destroy()
# Function to reset the window
def Reset():

    Msg.set("")
    key.set("")
    mode.set("")
    Result.set("")


# Show message button
btnTotal = Button(f1, padx=16, pady=1, bd=1, fg="black",
                  font=('Gilroy',18,'bold'), width=10,
                  text="Show Message", bg="white",
                  command=Results).grid(row=7, column=1)

# Reset button
btnReset = Button(f1, padx=16, pady=1, bd=1,
                  fg="black", font=('Gilroy',18,'bold'),
                  width=10, text="Reset", bg="white",
                  command=Reset).grid(row=7, column=2)

# Exit button
btnExit = Button(f1, padx=16, pady=1, bd=1,
                 fg="black", font=('Gilroy',18,'bold'),
                 width=10, text="Exit", bg="white",
                 command=qExit).grid(row=7, column=3)

# keeps window alive
root.mainloop()