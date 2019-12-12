import socket
import time
import msvcrt
import pickle
import threading
import sys
import math
from PIL import ImageTk, Image
import os
import base64
from cryptography.fernet import Fernet
from Crypto.Util import number
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
import tkinter
uInput = None
photoDict = {}
def send(event=None):
    global uInput
    uInput=my_msg.get()
    my_msg.set("")


def on_closing(event=None):
    top.quit()

top = tkinter.Tk()
top.title("Chat")
messages_frame = tkinter.Frame(top)
my_msg = tkinter.StringVar()
scrollbar = tkinter.Scrollbar(messages_frame)
msg_list = tkinter.Listbox(messages_frame, height=30, width=100, yscrollcommand=scrollbar.set)
scrollbar.pack(side=tkinter.RIGHT, fill=tkinter.Y)
msg_list.pack(side=tkinter.LEFT, fill=tkinter.BOTH)
msg_list.pack()
img = tkinter.Label()
img.pack()
def list_entry_clicked(*ignore):
    imgname=msg_list.get(msg_list.curselection()[0])
    img.config(image=photoDict[imgname])
msg_list.bind('<ButtonRelease-1>', list_entry_clicked)
messages_frame.pack()

entry_field = tkinter.Entry(top, textvariable=my_msg, width=80)
entry_field.bind("<Return>", send)
entry_field.pack()
send_button = tkinter.Button(top, text="Send", command=send)
send_button.pack()

top.protocol("WM_DELETE_WINDOW", on_closing)


def generate_partial_key(Pkey1, Pkey2, Prkey1):
    partial_key = Pkey1 ** Prkey1
    partial_key = partial_key % Pkey2
    return partial_key

def generate_full_key(partial_key_r, PrKey1, PKey2):
    full_key = partial_key_r ** PrKey1
    full_key = full_key % PKey2
    full_key = full_key
    return full_key



def main():
    MAGIC_1 = 'A'
    MAGIC_2 = 'K'
    token = None
    status = "offline"
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(0)

    full_key= None
    cPrivate=number.getPrime(16)
    Cpublic=number.getPrime(16)
    Hpublic = None
    Hpartial= None
    Cpartial = None
    full_key = None




    packet = {"MAGIC_1": MAGIC_1, "MAGIC_2": MAGIC_2, "mType": "getPublicKey", "token": token, "payload": Cpublic}
    ret = sock.sendto(pickle.dumps(packet), ('localhost', 10020))
    booler = True
    while (booler):
        try:
            data, server = sock.recvfrom(4096)
            rawData = pickle.loads(data)
            booler = False
        except:
            pass
    Hpublic = int(rawData["payload"])

    Cpartial = generate_partial_key(Cpublic, Hpublic, cPrivate)

    packet = {"MAGIC_1": MAGIC_1, "MAGIC_2": MAGIC_2, "mType": "getPartialKey", "token": token, "payload": Cpartial}
    ret = sock.sendto(pickle.dumps(packet), ('localhost', 10020))
    booler = True
    while (booler):
        try:
            data, server = sock.recvfrom(4096)
            rawData = pickle.loads(data)
            Hpartial = int(rawData["payload"])
            booler=False
        except:
            pass
    full_key = generate_full_key(Hpartial, cPrivate, Hpublic)

    print(full_key)
    full_key_encode = str(full_key).encode()
    salt = b'salt_'
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    key = base64.urlsafe_b64encode(kdf.derive(full_key_encode))
    f = Fernet(key)
    print(key)
    while True:
        global uInput
        time.sleep(0.02)
        if uInput:
            try:
                mType, payload = uInput.split("#")
            except:
                print("invalid output")
                uInput = None
                continue
            if mType == "login" and status == "offline":
                packet = {"MAGIC_1": MAGIC_1, "MAGIC_2": MAGIC_2, "mType": "login", "token": token, "payload": f.encrypt(payload)}
                print("sending")
                print(packet["payload"])
                ret = sock.sendto(pickle.dumps(packet), ('localhost', 10020))
                print("sent")
                booler=True
                while(booler):
                    try:
                        print("getting")
                        data, server = sock.recvfrom(4096)
                        rawData = pickle.loads(data)
                        print("got")
                        print(rawData["mType"])
                        if rawData["mType"] == "login_success":
                            token = rawData["token"]
                            print(token)
                            msg_list.insert(tkinter.END, "login_ack#success")
                            status="online"
                        elif rawData["mType"] == "login_fail":
                            msg_list.insert(tkinter.END,"login_ack#failed")
                        booler=False
                    except:
                        pass
            elif mType == "login" and status == "online":
                print("Already logged in")

            elif mType == "post" and status == "online":
                packet = {"MAGIC_1": MAGIC_1, "MAGIC_2": MAGIC_2, "mType": "post", "token": token, "payload": f.encrypt(payload)}
                ret = sock.sendto(pickle.dumps(packet), ('localhost', 10020))
                booler = True
                while (booler):
                    try:
                        data, server = sock.recvfrom(4096)
                        rawData = pickle.loads(data)
                        if rawData["mType"] == "post#ack":
                            msg_list.insert(tkinter.END,"post#ack")
                        elif rawData["mType"] == "post#fail":
                            msg_list.insert(tkinter.END,"error#post fail")
                        elif rawData["mType"] == "session#timeout":
                            status = "offline"
                            msg_list.insert(tkinter.END, "Session timeout: must login again")
                        booler = False
                    except:
                        pass
            elif mType == "logout" and status == "online":
                packet = {"MAGIC_1": MAGIC_1, "MAGIC_2": MAGIC_2, "mType": "logout", "token": token, "payload": None}
                ret = sock.sendto(pickle.dumps(packet), ('localhost', 10020))
                booler = True
                while (booler):
                    try:
                        data, server = sock.recvfrom(4096)
                        rawData = pickle.loads(data)
                        if rawData["mType"] == "logout#ack":
                            msg_list.insert(tkinter.END,"logout#ack")
                            status = "offline"
                        elif rawData["mType"] == "logout#fail":
                            msg_list.insert(tkinter.END, "error logging out")

                        booler = False
                    except:
                        pass
            elif mType == "post" and status == "offline":
                print("not logged in")
            elif mType == "subscribe" and status == "online":
                packet = {"MAGIC_1": MAGIC_1, "MAGIC_2": MAGIC_2, "mType": "subscribe", "token": token, "payload": f.encrypt(payload)}
                ret = sock.sendto(pickle.dumps(packet), ('localhost', 10020))
                booler = True
                while (booler):
                    try:
                        data, server = sock.recvfrom(4096)
                        rawData = pickle.loads(data)
                        if rawData["mType"] == "subscribe#ack":
                            msg_list.insert(tkinter.END, "subscribe#ack")
                        elif rawData["mType"] == "subscribe#fail":
                            msg_list.insert(tkinter.END, "subscribe#failure")
                        elif rawData["mType"] == "session#timeout":
                            status = "offline"
                            msg_list.insert(tkinter.END, "Session timeout: must login again")
                        booler = False
                    except:
                        pass
            elif mType == "subscribe" and status == "offline":
                print("not logged in")
            elif mType == "unsubscribe" and status == "online":
                packet = {"MAGIC_1": MAGIC_1, "MAGIC_2": MAGIC_2, "mType": "unsubscribe", "token": token, "payload": f.encrypt(payload)}
                ret = sock.sendto(pickle.dumps(packet), ('localhost', 10020))
                booler = True
                while (booler):
                    try:
                        data, server = sock.recvfrom(4096)
                        rawData = pickle.loads(data)
                        if rawData["mType"] == "unsubscribe#ack":
                            msg_list.insert(tkinter.END, "unsubscribe#ack")
                        elif rawData["mType"] == "unsubscribe#fail":
                            msg_list.insert(tkinter.END, "unsubscribe#failure")
                        elif rawData["mType"] == "session#timeout":
                            status = "offline"
                            msg_list.insert(tkinter.END,"Session timeout: must login again")
                        booler = False
                    except:
                        pass
            elif mType == "unsubscribe" and status == "offline":
                print("not logged in")
            elif mType == "retrieve" and status == "online":
                try:
                    n = int(payload)
                except:
                    print("retrieve num not Integer")
                    uInput = None
                    continue
                packet = {"MAGIC_1": MAGIC_1, "MAGIC_2": MAGIC_2, "mType": "retrieve", "token": token, "payload": f.encrypt(payload)}
                ret = sock.sendto(pickle.dumps(packet), ('localhost', 10020))
                booler = True
                while (booler):
                    try:
                        data, server = sock.recvfrom(4096)
                        rawData = pickle.loads(data)
                        if rawData["mType"] == "retrieve#ack":
                            msg_list.insert(tkinter.END, f.decrypt(rawData["payload"]))

                        elif rawData["mType"] == "retrieve#fail":
                            msg_list.insert(tkinter.END, "retrieve#failure")
                        elif rawData["mType"] == "session#timeout":
                            status = "offline"
                            msg_list.insert(tkinter.END, "Session timeout: must login again")
                        booler = False
                    except:
                        pass
            elif mType == "retrieve" and status == "offline":
                print("not logged in")
            elif mType == "spurious" and status == "online":
                packet = {"MAGIC_1": MAGIC_1, "MAGIC_2": MAGIC_2, "mType": "spurious", "token": token, "payload": f.encrypt(payload)}
                ret = sock.sendto(pickle.dumps(packet), ('localhost', 10020))
                booler = True
                while (booler):
                    try:
                        data, server = sock.recvfrom(4096)
                        rawData = pickle.loads(data)
                        if rawData["mType"] == "spurious#ack":
                            msg_list.insert(tkinter.END, "okay")
                        elif rawData["mType"] == "session#reset":
                            msg_list.insert(tkinter.END, "Error occurred session has been reset by server.")
                            status = "offline"
                        booler = False
                    except:
                        pass
            elif mType == "serverSpur" and status == "online":
                packet = {"MAGIC_1": MAGIC_1, "MAGIC_2": MAGIC_2, "mType": "serverSpur", "token": token,
                          "payload": None}
                ret = sock.sendto(pickle.dumps(packet), ('localhost', 10020))
                booler = True
            elif mType == "upload" and status == "online":
                packet = {"MAGIC_1": MAGIC_1, "MAGIC_2": MAGIC_2, "mType": "upload", "token": token,
                          "payload": f.encrypt(payload)}
                ret = sock.sendto(pickle.dumps(packet), ('localhost', 10020))
                __location__ = os.path.realpath(
                    os.path.join(os.getcwd(), os.path.dirname(__file__)))
                file = open(os.path.join(__location__, payload), "rb");
                data = file.read(1024)
                while(data):
                    if(sock.sendto(f.encrypt(data), ('localhost', 10020))):
                        data = file.read(1024)
                file.close()
            uInput = None
        else:
            try:
                data, server = sock.recvfrom(4096)
                rawData = pickle.loads(data)
                if rawData["mType"] == "retrieve#ack":
                    msg_list.insert(tkinter.END, f.decrypt(rawData["payload"]))
                elif rawData["mType"] == "forward#message":
                    msg_list.insert(tkinter.END, f.decrypt(rawData["payload"]))
                elif rawData["mType"] == "forward#fail":
                    msg_list.insert(tkinter.END, "forwarding#failure")
                elif rawData["mType"] == "session#reset":
                    msg_list.insert(tkinter.END, "Session reset triggered by server")
                    status = "offline"
                elif rawData["mType"] == "session#timeout":
                    msg_list.insert(tkinter.END, "timeout happened")
                    status = "offline"
                elif rawData["mType"] == "file#forward":
                    __location__ = os.path.realpath(
                        os.path.join(os.getcwd(), os.path.dirname(__file__)))
                    username, fileName = f.decrypt(rawData["payload"]).split("&")
                    file = open(os.path.join(__location__, fileName), 'wb')

                    booler = True
                    while (booler):
                        try:
                            data, address = sock.recvfrom(4096)
                            booler = False
                        except:
                            pass
                    try:
                        while (data):
                            print("getting it")
                            file.write(f.decrypt(data))
                            sock.settimeout(2)
                            data, address = sock.recvfrom(4096)
                    except:
                        pass
                    print("before")
                    file.close()
                    msg_list.insert(tkinter.END, "<{}> {}".format(username, fileName))
                    path=(os.path.join(__location__,fileName))
                    print(path)
                    path.encode('unicode_escape')
                    photo=ImageTk.PhotoImage(Image.open(path))
                    photoDict["<{}> {}".format(username, fileName)]=photo
                    print(photoDict)
                    print("after")
                else:
                    print(rawData)
                    packet = {"MAGIC_1": MAGIC_1, "MAGIC_2": MAGIC_2, "mType": "serverReset", "token": token,
                              "payload": None}
                    ret = sock.sendto(pickle.dumps(packet), ('localhost', 10020))
                    status = "offline"
                    msg_list.insert(tkinter.END, "Session reset triggered by client")


            except:
                pass


t = threading.Thread(target=main)
t.daemon = True
t.start()

while True:
    tkinter.mainloop()



