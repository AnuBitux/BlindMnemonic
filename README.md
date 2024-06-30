# BlindMnemonic
This tool allows two operators to create a mnemonic seed so that nobody has access to all the words.\
Each operator obtains a part of the mnemonic seed. At the end, the tool provides some deposit addresses related to the generated mnemonic, without disclosing it.

## How to use the tool
Install python virtual environments
```
sudo apt install python3-virtualenv
```
Clone this tool and move to its folder
```
git clone github.com/ASeriousMister/BlindMnemonic
cd /path/BlindGen
```
Create a virtual environment
```
virtualenv bmve
```
Activate it
```
source bmve/bin/activate
```
Install dependencies
```
pip3 install -r requirements.txt
```
install wkhtmltopdf to generate printable PDFs
```
sudo apt install wkhtmltopdf
```
Install evince as default pdf reader
```
sudo apt install evince
```
Launch the tool
```
pytohn3 blindmnemonic.py
```
Take note of the parts of the mnemonic and store them in a safe place, they cannot be recovered.\
At the end, a printable pdf with the desired deposit address and the related QR code is shown and saved in the PaperWallet folder.\
To read QR codes, QtQR may be useful.
```
sudo apt install qtqr
```
## Disclaimer
This tool has been designed to generate crypto wallets allowing nobody to have access to the whole menmonic seed. It works only if used properly. End users are responsible for their actions and for any misuse.\
End users are also responsible for storing the private keys in a safe way. The tool does not store any tipe of information related to the private keys and in no way it will be able to recover access to lost information.\
This tool is provided 'as is' without any warranty of any kind, express or implied. The developers make no warranty that the tool will be free from errors, defects or inaccuracies.\
In no event shall the developers be liable for any damages or losses incurred as a result of using this tool.

