# Realizați un utilitar care să împartă un fișier în n fișiere. Pentru a recompune fișierul, va fi necesară prezența a
# cel puțin m dintre ele.
import os
import sys
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Protocol.SecretSharing import Shamir
from binascii import hexlify, unhexlify


def split():
    try:
        if len(sys.argv) != 5:
            raise ValueError("Numar incorect de argumente!\nExemplu de comanda valida:\npy secret_share.py -split n m "
                             "file.txt\n")

        n = int(sys.argv[2])
        m = int(sys.argv[3])
        file = sys.argv[4]

        if n <= 0:
            raise ValueError(f"Error: Numarul de fisere in care se imparte {file} trebuie sa fie pozitiv.")

        if m <= 0:
            raise ValueError(f"Error: Numarul de fisiere necesare pentru a reconstrui {file} trebuie sa fie pozitiv.")

        if n < m:
            raise ValueError(f"Error: Nu este posibil sa fie necesare mai multe fisiere pentru a reconstrui {file} "
                             f"decat numarul in care a fost impartit.")

        key = get_random_bytes(16)
        shares = Shamir.split(m, n, key)

        parts = set()

        for idx, share in shares:
            part = f"part{idx}.secret"
            parts.add(part)

            try:
                with open(part, 'wb') as fo:
                    fo.write(bytes((str(idx) + ","), encoding="ascii"))
                    fo.write(hexlify(share))
            except Exception as e:
                print("Fisierul nu a putut fi creat:", e)

        for filename in os.listdir():
            if filename.startswith("part") and filename.endswith(".secret") and filename not in parts:
                os.remove(filename)

        try:
            with open(file, 'rb') as file_input, open("encrypt.txt", "wb") as file_output:
                cipher = AES.new(key, AES.MODE_EAX)
                nonce = cipher.nonce
                ct, tag = cipher.encrypt(file_input.read()), cipher.digest()
                file_output.write(nonce + tag + ct)
        except FileNotFoundError:
            print(f"Fisierul {file} nu a fost gasit.")
    except Exception as e:
        print("Error:", e)


def recompose():
    try:
        if len(sys.argv) < 4:
            raise ValueError("Numar incorect de argumente!\nExemplu de comenzi valide:\npy secret_share.py -recompose "
                             "file1.secret file2.secret")

        shares = []
        for file_name in sys.argv[2:]:
            try:
                with open(file_name, "rb") as fi:
                    lines = fi.readlines()
                    for line in lines:
                        idx, share = line.decode("ascii").split(",")
                        shares.append((int(idx), unhexlify(share)))
            except Exception as e:
                print("Error:", e)

        key = Shamir.combine(shares)

        try:
            with open("encrypt.txt", "rb") as fi:
                nonce, tag = [fi.read(16) for _ in range(2)]
                cipher = AES.new(key, AES.MODE_EAX, nonce)
                try:
                    result = cipher.decrypt(fi.read())
                    cipher.verify(tag)
                    with open("output.txt", "wb") as fo:
                        fo.write(bytes(result))
                except ValueError:
                    print("Nu se poate reconstrui fiserul doar din partile date.")
        except FileNotFoundError:
            print("Fisierul de decriptat nu a fost gasit.")
    except Exception as e:
        print("Error: ", e)


class Secret_Share:
    def __init__(self):
        try:
            self.param1 = sys.argv[1]
            if self.param1 == "-split":
                split()
            elif self.param1 == "-recompose":
                recompose()
            else:
                raise ValueError("Parametru invalid.\nExemplu de comenzi valide:\npy secret_share.py -split n m "
                                 "file.txt\npy secret_share.py -recompose file1.secret file2.secret")
        except Exception as e:
            print("Error:", e)


if __name__ == '__main__':
    secret_share_obj = Secret_Share()
