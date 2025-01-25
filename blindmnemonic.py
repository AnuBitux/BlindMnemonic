import tkinter as tk
from tkinter import messagebox
from tkinter import StringVar
import sys
import random
import os
import hashlib
from hdwallet import HDWallet
from hdwallet.symbols import BTC, ETH, LTC, DASH, ZEC, DOGE, BTCTEST
import qrcode
import pdfkit
import os
from os.path import exists
import subprocess
import binascii
from hdwallet.utils import is_mnemonic


# Change Working Directory for AnuBitux environment
user_folder = os.getlogin()
os.chdir('/home/' + user_folder + '/Documents/')


# Obtain secure random numbers
system_random = random.SystemRandom()
# Global variables
coin_sel = None
len_sel = None
len_sel_int = None
remaining = ''
half_mnemonic_string = ''
sec_half_mnemonic_string = ''
mnemonic_list = []
bin_first_half = ''


# Generate QR codes from strings
def makeqr(keystr, filename):
    img = qrcode.make(keystr)
    type(img)
    filename = 'PaperWallet/' + filename
    img.save(filename)


# Show popup when user does some shit
def show_popup(message):
    popup = tk.Tk()
    popup.title("WARNING!")
    label = tk.Label(popup, text=message)
    label.pack()
    ok_button = tk.Button(popup, text="Ok", command=popup.destroy)
    ok_button.pack()
    popup.mainloop()


# Converting hexadecimal string into a string of 0s and 1s
def hex_to_binary(hex_str):
    # Convert the hexadecimal hash string to an integer
    integer_value = int(hex_str, 16)
    # Convert the integer to a binary string and remove the '0b' prefix (first two characters)
    binary_str = bin(integer_value)[2:]
    return binary_str

# Converting a string made by 0s and 1s in a mnemonic phrase stored as a list
def binary_string_to_mnemonic(binary_string, word_list_file):
    if len_sel_int == 12:
        bytes = 16
    elif len_sel_int == 24:
        bytes = 32
    tmp_bin = binary_string
    # convert string with 0s and 1s to hex and to binary
    bin_list = []
    start = 0
    part = 4
    while start < len(tmp_bin):  # Splitting string in 4 digits parts
        bin_list.append(tmp_bin[start: start + part])
        start += part
    # convert list with four 0 and 1 digits to list with hexadecimal letters
    hex_list = []
    for bn in bin_list:
        hex_list.append(binToHexa(bn))
    hex_ent = ''.join(hex_list)  # creates hexadecimal string of entropy
    if (len(hex_ent))%2 != 0:
        hex_ent = hex_ent.zfill((len(hex_ent))+1)    # sometimes binascii get odd string, putting a 0 into the string to avoid it
    tmp_bin = binascii.unhexlify(hex_ent)  # binary of entropy
    tmp_hex = binascii.hexlify(tmp_bin)  # hexadecimal of entropy
    str_hash = hashlib.sha256(tmp_bin).hexdigest()  # hashing binary of entropy
    # Converting hash to binary
    int_hash = int(str_hash, base=16)
    bin_hash = str(bin(int_hash))[2:]
    # Adding checksum to entropy
    checksum_length = int((len(binary_string))/32)
    checksum = bin_hash[0:checksum_length]  # Getting first digits of hash (4 to 8 depending on entropy)
    binary_seed = (bin(int(tmp_hex, 16))[2:].zfill(bytes * 8) + bin(int(str_hash, 16))[2:].zfill(256)[: bytes * 8 // 32])

    index_list = [] # list of the indexes of the words into the wordlist
    start = 0
    part = 11 # each index is made by 11 bits
    while start < len(binary_seed):
        index_list.append(binary_seed[start: start + part])
        start += part # adds 11 bits at each iteration

    # Converting binary indexes to integer
    index_list_int = []
    b = 0
    while b < len(index_list):
        index_list_int.append(int(index_list[b], 2))
        b += 1

    f = open('/opt/Tools/WalletGen/BlindMnemonic/Wordlists/b39en', 'r')  # Opening English wordlist, just because the others are useless
    mnemonic = []
    w = 0
    while w < len(index_list_int):
        f.seek(0) # starts from the beginning of the file
        for i, line in enumerate(f):
            if i == index_list_int[w]:
                mnemonic.append(line.strip('\n'))
        w += 1

    return mnemonic   # returns a list, useful to remove useless words for pdf files


# Converts string with 0 and 1 to hexadecimal
def binToHexa(n):
    bnum = int(n)
    temp = 0
    mul = 1
    # counter to check group of 4
    count = 1
    # char array to store hexadecimal number
    hexaDeciNum = ['0'] * 100
    # counter for hexadecimal number array
    i = 0
    while bnum != 0:
        rem = bnum % 10
        temp = temp + (rem * mul)
        # check if group of 4 completed
        if count % 4 == 0:
            # check if temp < 10
            if temp < 10:
                hexaDeciNum[i] = chr(temp + 48)
            else:
                hexaDeciNum[i] = chr(temp + 55)
            mul = 1
            temp = 0
            count = 1
            i = i + 1
        # group of 4 is not completed
        else:
            mul = mul * 2
            count = count + 1
        bnum = int(bnum / 10)
    # check if at end the group of 4 is not completed
    if count != 1:
        hexaDeciNum[i] = chr(temp + 48)
    # check at end the group of 4 is completed
    if count == 1:
        i = i - 1
    return hexaDeciNum[i]


class ZeroWindow:
    def __init__(self, master):
        self.master = master
        self.master.title("Choose lenght")
        self.master.geometry("450x150")

        # Select from 12 and 24 words mnemonics, metamask allows 12, use enkript (mew) for 24 words mnemonics with EVM stuff
        self.len_sel = tk.StringVar()
        self.len_sel.set("12")  # Default
        self.menu = tk.OptionMenu(master, self.len_sel, "12", "24")
        self.menu.pack()

        # Starts the process, where two users have to generate two parts of a mnemonic seed
        self.button2 = tk.Button(master, text="Start generation process", command=self.new_window, bg="black", fg="green")
        self.button2.pack()

    def new_window(self):
        global len_sel
        global len_sel_int
        len_sel = self.len_sel.get()
        if len_sel == "12":
            len_sel_int = 12
        elif len_sel == "24":
            len_sel_int = 24
        self.master.withdraw()
        first_window = tk.Toplevel(self.master)
        first_window.geometry("450x150")
        FirstWindow(first_window)


class FirstWindow:
    def __init__(self, master):
        self.master = master
        self.master.title("Operator 1")
        self.master.geometry("450x150")

        self.input_label = tk.Label(master, text="Type some random text:")
        self.input_label.pack()

        self.input_text = tk.Entry(master)
        self.input_text.pack()

        # Opens a pdf with the part of the private key and QR codes
        self.button1 = tk.Button(master, text="Generate first words", command=self.gen_first_half, bg="black", fg="blue")
        self.button1.pack()

        # Closes and deletes pdf file and qr code and shows a new window for the second user
        self.button2 = tk.Button(master, text="End, 2nd operator\'s turn", command=self.new_user_turn, bg="black", fg="blue")
        self.button2.pack()

    def gen_first_half(self):
        global half_key
        global remaining
        global half_mnemonic_string
        global bin_first_half
        input_text = self.input_text.get()
        if input_text == '':
            show_popup('Please insert some text in the proper box before generating the 1/2 part of the mnemonic seed')
        elif exists('PaperWallet/halfmnem1.pdf'):
            show_popup('You already created the first part of the mnemonic seed, click on the other button to go to the next step')
        else:
            # Add random system entropy
            extra_ent = str(system_random.randint(0, sys.maxsize))
            extra_ent += str(system_random.randint(0, sys.maxsize))
            # create entropy source joining random word to random system entropy
            ent_source = input_text + extra_ent
            # obtain first 128 bits of the private key
            half_key = hashlib.md5(ent_source.encode('utf-8')).hexdigest()
            if len_sel_int == 12: # If lenght has been set to 12, using only odd chars of the md5 checksum, since only a total of 128 bits is expected
                odd_characters = []  # For storing odd characters
                for i in range(len(half_key)):
                    if i % 2 != 0:  # check if the index is odd
                        odd_characters.append(half_key[i])
                half_key = ''.join(odd_characters) # convert list to string
            bin_first_half = hex_to_binary(half_key)
            i = 0
            index_list = []
            while True:
                index = bin_first_half[i:(i+11)]
                if len(index) == 11:
                    i += 11
                    index_list.append(index)
                else:
                    remaining = index # stores the remaining part of the binary string that has few than 11 bits, if needed in the part
                    break

            # Converting binary indexes to integer
            index_list_int = []
            b = 0
            while b < len(index_list):
                index_list_int.append(int(index_list[b], 2))
                b += 1

            f = open('/opt/Tools/WalletGen/BlindMnemonic/Wordlists/b39en', 'r')  # Opening English wordlist, just because the others are useless
            half_mnemonic = []
            w = 0
            while w < len(index_list_int):
                f.seek(0)
                for i, line in enumerate(f):
                    if i == index_list_int[w]:
                        half_mnemonic.append(line.strip('\n'))
                w += 1
            f.close()
            half_mnemonic_string = ' '.join(half_mnemonic) # string type needed to put into pdf file

            # make printable pdf
            ft = open('PaperWallet/temp.html', 'w')
            ft.write('<!doctype html>\n<body>')
            if exists('PaperWallet/logo.png'):
                ft.write('<p><img src="logo.png" width="100" height="100"></p>')
            ft.write('<h4>Mnemonic, part 1/2</h4>')
            ft.write('<p><strong>First words: </strong>' + half_mnemonic_string + '</p>')
            ft.write('<p></p><p></p><p><em>Made with blindmnem.py<br>More info at https://anubitux.org</em></p>')
            ft.write('</body>')
            ft.close()
            pdfkit.from_file('PaperWallet/temp.html', 'PaperWallet/halfmnem1.pdf', options={"enable-local-file-access": ""})
            os.remove('PaperWallet/temp.html')
            subprocess.run(['xdg-open', 'PaperWallet/halfmnem1.pdf'])

    def new_user_turn(self):
        if exists('PaperWallet/halfmnem1.pdf'):
            os.system('lsof -t PaperWallet/halfmnem1.pdf | xargs kill')
            os.remove('PaperWallet/halfmnem1.pdf')
            self.master.withdraw()
            second_window = tk.Toplevel(self.master)
            second_window.geometry("450x150")
            SecondWindow(second_window)
        else:
            show_popup('Before proceeding, type some text in the box, generate the 1/2 part of the private mnemonic seed and store it in a safe place')


class SecondWindow:
    def __init__(self, master):
        self.master = master
        self.master.title("Operator 2")
        self.master.geometry("450x150")

        self.input_label = tk.Label(master, text="Type some random text:")
        self.input_label.pack()

        self.input_text = tk.Entry(master)
        self.input_text.pack()

        # Opens a pdf with the part of the private key and QR codes
        self.button1 = tk.Button(master, text="Generate remaining words", command=self.gen_second_half, bg="black", fg="blue")
        self.button1.pack()

        # Closes and deletes pdf file and qr code and opens a new window to generate receiving addresses
        self.button2 = tk.Button(master, text="End, obtain addresses", command=self.go_to_pub_gen, bg="black", fg="blue")
        self.button2.pack()


    def gen_second_half(self):
        global sec_half_key
        global sec_half_mnemonic_string
        global mnemonic_list
        input_text = self.input_text.get()
        if input_text == '':
            show_popup('Please insert some text in the proper box before generating the 2/2 part of the mnemonic seed')
        elif exists('PaperWallet/halfmnem2.pdf'):
            show_popup('You already created the second part of the mnemonic seed, click on the other button to go to the next step')
        else:
            # Add random system entropy
            extra_ent = str(system_random.randint(0, sys.maxsize))
            extra_ent += str(system_random.randint(0, sys.maxsize))
            # create entropy source joining random word to random system entropy
            ent_source = input_text + extra_ent
            # obtain first 128 bits from the entropy
            sec_half_key = hashlib.md5(ent_source.encode('utf-8')).hexdigest()
            if len_sel_int == 12: # If lenght is set to 12, only 64 bits needed
                odd_characters = []  # For storing odd characters
                for i in range(len(sec_half_key)):
                    if i % 2 != 0:  # check if the index is odd
                        odd_characters.append(sec_half_key[i])
                sec_half_key = ''.join(odd_characters)
            bin_sec_half = hex_to_binary(sec_half_key)
            bin_seed = bin_first_half + bin_sec_half
            # Now add checksum and other stuff, generate the full mnemonic, ignore the first 5 or the first 11 words when creating pdf
            f = open('/opt/Tools/WalletGen/BlindMnemonic/Wordlists/b39en', 'r')  # Opening English wordlist, just because the others are useless
            mnemonic_list = binary_string_to_mnemonic(bin_seed, f)
            f.close()

            # make printable pdf
            ft = open('PaperWallet/temp.html', 'w')
            ft.write('<!doctype html>\n<body>')
            if exists('PaperWallet/logo.png'):
                ft.write('<p><img src="logo.png" width="100" height="100"></p>')
            ft.write('<h4>Mnemonic, part 2/2</h4>')
            if len_sel_int == 12:
                sec_half_mnemonic_string = ' '.join(mnemonic_list[5:])
                ft.write('<p><strong>Last words: </strong>' + sec_half_mnemonic_string + '</p>')
            elif len_sel_int == 24:
                sec_half_mnemonic_string = ' '.join(mnemonic_list[11:])
                ft.write('<p><strong>Last words: </strong>' + sec_half_mnemonic_string + '</p>')
            ft.write('<p></p><p></p><p><em>Made with blindmnem.py<br>More info at https://anubitux.org</em></p>')
            ft.write('</body>')
            ft.close()
            pdfkit.from_file('PaperWallet/temp.html', 'PaperWallet/halfmnem2.pdf', options={"enable-local-file-access": ""})
            os.remove('PaperWallet/temp.html')
            subprocess.run(['xdg-open', 'PaperWallet/halfmnem2.pdf'])


    def go_to_pub_gen(self):
        if exists('PaperWallet/halfmnem2.pdf'):
            os.system('lsof -t PaperWallet/halfmnem2.pdf | xargs kill')
            os.remove('PaperWallet/halfmnem2.pdf')
            self.master.withdraw()
            third_window = tk.Toplevel(self.master)
            third_window.geometry("450x150")
            ThirdWindow(third_window)
        else:
            show_popup('Before proceeding, type some text in the box, generate the 2/2 part of the mnemonic seed and store it in a safe place')


class ThirdWindow:
    def __init__(self, master):
        self.master = master
        self.master.title("Generating addresses")
        self.master.geometry("450x150")

        # Available coins list
        self.coin_sel = tk.StringVar()
        self.coin_sel.set("Bitcoin")  # Default
        self.menu = tk.OptionMenu(master, self.coin_sel, "Bitcoin", "Ethereum (EVM)", "Litecoin", "Dash", "ZCash", "Dogecoin", "Bitcoin testnet")
        self.menu.pack()

        # Generates pdf with public addresses and QR codes
        self.button2 = tk.Button(master, text="Generate public address", command=self.gen_public_paper, bg="black", fg="blue")
        self.button2.pack()

        # Closes the tool
        self.button3 = tk.Button(master, text="Close", command=self.close_all, bg="black", fg="red")
        self.button3.pack()


    def gen_public_paper(self):
        global coin_sel
        coin_sel = self.coin_sel.get()
        # Security checks
        if half_mnemonic_string == '' or sec_half_mnemonic_string == '':
            show_popup('Something has gone wrong, consider restarting the process')
            exit()
        if len(mnemonic_list) != 12 and len(mnemonic_list) != 24:
            show_popup('Something has gone wrong, consider restarting the process')
            exit()
        if is_mnemonic(' '.join(mnemonic_list), 'english') is False:
        	show_popup('Something has gone wrong, consider restarting the process')
        	exit()
        first_words = half_mnemonic_string.split()
        ind_test = 0
        while ind_test < len(first_words):
            if first_words[ind_test] != mnemonic_list[ind_test]:
                show_popup('Something has gone damn wrong, consider restarting the process')
                exit()
            else:
                ind_test += 1
                
        if coin_sel == 'Bitcoin':
            hdwallet: HDWallet = HDWallet(symbol=BTC)
            hdwallet.from_mnemonic(mnemonic=(' '.join(mnemonic_list)), passphrase='', language='english')
            hdwallet.from_path(f"m/84'/0'/0'/0/0")
            address = hdwallet.p2wpkh_address()
            Address_type = 'Bitcoin bech32 public address'
            der_path = "m/84'/0'/0'/0"
        elif coin_sel == 'Ethereum (EVM)':
            hdwallet: HDWallet = HDWallet(symbol=ETH)
            hdwallet.from_mnemonic(mnemonic=(' '.join(mnemonic_list)), passphrase='', language='english')
            hdwallet.from_path(f"m/44'/60'/0'/0/0")
            address = hdwallet.p2pkh_address()
            Address_type = 'Ethereum or EVM based account'
            der_path = "m/44'/60'/0'/0"
        elif coin_sel == 'Litecoin':
            hdwallet: HDWallet = HDWallet(symbol=LTC)
            hdwallet.from_mnemonic(mnemonic=(' '.join(mnemonic_list)), passphrase='', language='english')
            hdwallet.from_path(f"m/84'/2'/0'/0/0")
            address = hdwallet.p2wpkh_address()
            Address_type = 'Litecoin bech32 public address'
            der_path = "m/84'/2'/0'/0"
        elif coin_sel == 'Dash':
            hdwallet: HDWallet = HDWallet(symbol=DASH)
            hdwallet.from_mnemonic(mnemonic=(' '.join(mnemonic_list)), passphrase='', language='english')
            hdwallet.from_path(f"m/44'/5'/0'/0/0")
            address = hdwallet.p2pkh_address()
            Address_type = 'Dash public address'
            der_path = "m/44'/5'/0'/0"
        elif coin_sel == 'ZCash':
            hdwallet: HDWallet = HDWallet(symbol=ZEC)
            hdwallet.from_mnemonic(mnemonic=(' '.join(mnemonic_list)), passphrase='', language='english')
            hdwallet.from_path(f"m/44'/133'/0'/0/0")
            address = hdwallet.p2pkh_address()
            Address_type = 'ZCash public address'
            der_path = "m/44'/133'/0'/0"
        elif coin_sel == 'Dogecoin':
            hdwallet: HDWallet = HDWallet(symbol=DOGE)
            hdwallet.from_mnemonic(mnemonic=(' '.join(mnemonic_list)), passphrase='', language='english')
            hdwallet.from_path(f"m/44'/3'/0'/0/0")
            address = hdwallet.p2pkh_address()
            Address_type = 'Dogecoin public address'
            der_path = "m/44'/3'/0'/0"
        elif coin_sel == 'Bitcoin testnet':
            hdwallet: HDWallet = HDWallet(symbol=BTCTEST)
            hdwallet.from_mnemonic(mnemonic=(' '.join(mnemonic_list)), passphrase='', language='english')
            hdwallet.from_path(f"m/44'/1'/0'/0/0")
            address = hdwallet.p2pkh_address()
            Address_type = 'Bitcoin testnet public address'
            der_path = "m/44'/1'/0'/0"

        # Creating QR code for the public address
        makeqr(address,'public_address.png')

        # Creating PDF
        ft = open('PaperWallet/temp.html', 'w')
        ft.write('<!doctype html>\n<body>')
        if exists('PaperWallet/logo.png'):
            ft.write('<p><img src="logo.png" width="100" height="100"></p>')
        ft.write(f'<h4>{Address_type}</h4>')
        ft.write('<h5><strong>Address: </strong>' + address + '</h5>')
        ft.write('<p><img src="public_address.png" width="200" height="200"></p>')
        ft.write('<p></p><p></p><p><em>Make sure to have both parts of the menmonic seed before sending funds<br></em></p>')
        ft.write('<p></p><p></p><p><em>Made with blindmnem.py<br>More info at https://anubitux.org</em></p>')
        ft.write('</body>')
        ft.close()
        pdfkit.from_file('PaperWallet/temp.html', 'PaperWallet/Public.pdf', options={"enable-local-file-access": ""})
        os.remove('PaperWallet/temp.html')
        os.remove('PaperWallet/public_address.png')
        subprocess.run(['xdg-open', 'PaperWallet/Public.pdf'])

    def close_all(self):
        self.master.destroy()
        sys.exit()


def main():
    root = tk.Tk()
    app = ZeroWindow(root)
    root.mainloop()

if __name__ == "__main__":
    main()
