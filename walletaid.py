"""
Walletaid-Z created by Dwerg using Python 2.7
"""

import hashlib
import binascii
from os import path
from Tkinter import *

privprefix = "ab36"

if not path.exists("wallet.dat"):
    print "The wallet.dat file is not in folder or has different name"
    exit(0)

#Loads wallet.dat into lists of addresses and private keys
with open('wallet.dat', 'rb') as f:
    count = 0
    klist = []
    header = binascii.unhexlify("200001")
    data = f.read()
    header_index = data.find(header, 0)
    key = data[header_index + len(header): header_index + len(header) + 32]
    while True:
        if key not in klist:
            count += 1
            klist.append(key)
            
        header_index = data.find(header,header_index + len(header) + 32)
        if header_index >= 0:
            key = data[header_index + len(header): header_index + len(header) + 32]
        else:
            break
print "Wallet scanned!\nFound {} keys in wallet.dat\n".format(count)

#Base58 encoder
__b58chars = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'
__b58base = len(__b58chars)

def b58encode(v):
    """ encode v, which is a string of bytes, to base58.
    """

    long_value = 0L
    for (i, c) in enumerate(v[::-1]):
        long_value += (256**i) * ord(c)

    result = ''
    while long_value >= __b58base:
        div, mod = divmod(long_value, __b58base)
        result = __b58chars[mod] + result
        long_value = div
    result = __b58chars[long_value] + result

    nPad = 0
    for c in v:
        if c == '\0': nPad += 1
        else: break

    return (__b58chars[0]*nPad) + result

#SHA-256 hashception function
def Hash(data):
    return hashlib.sha256(hashlib.sha256(data).digest()).digest()

#Takes hexadecimal private key, spits out WIF
def hashtowif(b):
    presha = binascii.unhexlify(privprefix) + b
    h = Hash(presha)
    key = presha + h[0:4]
    return b58encode(key)

#GUI and code for printing output to textbox and file.
print "Opening GUI"

#Prints all keys.
def getAll():
    frame1.destroy()
    frame3.grid()
    keyfile = open("foundkeys.txt","w")
    count = 0
    maxcount = len(klist)
    for k in klist:
        count += 1
        privkey = hashtowif(k)
        keyfile.write("Private key: {}\n\n".format(privkey))

        keyCount.set("Hashing key {}/{}".format(count, maxcount))
        
        outBox.configure(state='normal')
        outBox.insert('end', "Private key: {}\n\n".format(privkey))
        outBox.configure(state='disabled')
        outBox.yview_moveto(1.0)
        outBox.update()
        
    outBox.configure(state='normal')
    outBox.insert("end", "Done!\nSaved found keys to 'foundkeys.txt'")
    outBox.configure(state='disabled')
    outBox.yview_moveto(1.0)

#Quits the program.
def kill():
    root.destroy()

#Sets up the GUI frames.
root = Tk()
root.title("Walletaid Z")
root.resizable(width=False, height=False)

#Startup frame
frame1 = Frame(root)
frame1.grid()

#instruction=Label(frame1,
#    text="Walletaid Z",
#    font=("", 20 , "bold")
#    )
#instruction.grid(row=0, column=1)

selButton1 = Button(frame1, height=2, width=10, text="Get keys", font=("", 20 , "bold"), command=getAll)
selButton1.grid(row=1, column=1)

spacing = Frame(frame1, height=15)
spacing1 = Frame(frame1, height=15)
spacing2 = Frame(frame1, width=15)
spacing3 = Frame(frame1, width=15)
spacing.grid(row=0, columnspan=2)
spacing1.grid(row=2, columnspan=2)
spacing2.grid(rowspan=3)
spacing3.grid(column=2, rowspan=3)
#End startup frame

#Output frame
frame3 = Frame(root)

keyCount = StringVar()
infoText = Label(frame3, textvariable=keyCount, font=("", 11 , "bold"))
infoText.grid(column=1)

scrollbar = Scrollbar(frame3)
outBox = Text(frame3, height=20, width=70, state="disabled", yscrollcommand=scrollbar.set)

outBox.grid(row=1, column=1)
scrollbar.grid(row=1, column=2, sticky=N+S)
scrollbar.config(command=outBox.yview)

closeButton = Button(frame3, height=2, width=15, text="Close", font=("", 11 , "bold"), command=kill)
closeButton.grid(row=2, column=1, pady=10)

spacing6 = Frame(frame3, width=10)
spacing7 = Frame(frame3, width=10)
spacing6.grid(column=0, rowspan=2)
spacing7.grid(column=3, rowspan=2)
#End output frame

#Launches the GUI
root.mainloop()
