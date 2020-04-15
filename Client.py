import socket
import time
import pickle
import threading
import sys
import math
import os
import base64
from cryptography.fernet import Fernet
from Crypto.Util import number
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from ipify import get_ip
ip = get_ip()
ip=str(ip)
def generate_partial_key(Pkey1, Pkey2, Prkey1):
    partial_key = Pkey1 ** Prkey1
    partial_key = partial_key % Pkey2
    return partial_key

def generate_full_key(partial_key_r, PrKey1, PKey2):
    full_key = partial_key_r ** PrKey1
    full_key = full_key % PKey2
    full_key = full_key
    return full_key


uInput = None

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

    """
    packet = {"MAGIC_1": MAGIC_1, "MAGIC_2": MAGIC_2, "mType": "getIP", "token": token, "payload": ip}
    ret = sock.sendto(pickle.dumps(packet), ('3.16.183.65', 10020))
    print("sent to{}".format(ip))
    booler = True
    while (booler):
        try:
            data, server = sock.recvfrom(4096)
            print("gotit")
            rawData = pickle.loads(data)
            booler = False
        except:
            pass

    """
    print("here")
    packet = {"MAGIC_1": MAGIC_1, "MAGIC_2": MAGIC_2, "mType": "getPublicKey", "token": token, "payload": Cpublic}
    ret = sock.sendto(pickle.dumps(packet), ('3.16.183.65', 10020))
    print("sent")
    booler = True
    while (booler):
        try:
            data, server = sock.recvfrom(4096)
            print("gotit")
            rawData = pickle.loads(data)
            booler = False
        except:
            pass
    Hpublic = int(rawData["payload"])

    Cpartial = generate_partial_key(Cpublic, Hpublic, cPrivate)

    packet = {"MAGIC_1": MAGIC_1, "MAGIC_2": MAGIC_2, "mType": "getPartialKey", "token": token, "payload": Cpartial}
    ret = sock.sendto(pickle.dumps(packet), ('3.16.183.65', 10020))
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
                ret = sock.sendto(pickle.dumps(packet), ('3.16.183.65', 10020))
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
                            print("login_ack#success")
                            status="online"
                        elif rawData["mType"] == "login_fail":
                            print("login_ack#failed")
                        booler=False
                    except:
                        pass
            elif mType == "login" and status == "online":
                print("Already logged in")

            elif mType == "post" and status == "online":
                packet = {"MAGIC_1": MAGIC_1, "MAGIC_2": MAGIC_2, "mType": "post", "token": token, "payload": f.encrypt(payload)}
                ret = sock.sendto(pickle.dumps(packet), ('3.16.183.65', 10020))
                booler = True
                while (booler):
                    try:
                        data, server = sock.recvfrom(4096)
                        rawData = pickle.loads(data)
                        if rawData["mType"] == "post#ack":
                            print("post#ack")
                        elif rawData["mType"] == "post#fail":
                            print("error#post fail")
                        elif rawData["mType"] == "session#timeout":
                            status = "offline"
                            print("must login first")
                        booler = False
                    except:
                        pass
            elif mType == "logout" and status == "online":
                packet = {"MAGIC_1": MAGIC_1, "MAGIC_2": MAGIC_2, "mType": "logout", "token": token, "payload": None}
                ret = sock.sendto(pickle.dumps(packet), ('3.16.183.65', 10020))
                booler = True
                while (booler):
                    try:
                        data, server = sock.recvfrom(4096)
                        rawData = pickle.loads(data)
                        if rawData["mType"] == "logout#ack":
                            print("logout#ack")
                            status = "offline"
                        elif rawData["mType"] == "logout#fail":
                            print("error logging out")

                        booler = False
                    except:
                        pass
            elif mType == "post" and status == "offline":
                print("not logged in")
            elif mType == "subscribe" and status == "online":
                packet = {"MAGIC_1": MAGIC_1, "MAGIC_2": MAGIC_2, "mType": "subscribe", "token": token, "payload": f.encrypt(payload)}
                ret = sock.sendto(pickle.dumps(packet), ('3.16.183.65', 10020))
                booler = True
                while (booler):
                    try:
                        data, server = sock.recvfrom(4096)
                        rawData = pickle.loads(data)
                        if rawData["mType"] == "subscribe#ack":
                            print("subscribe#ack")
                        elif rawData["mType"] == "subscribe#fail":
                            print("subscribe#failure")
                        elif rawData["mType"] == "session#timeout":
                            status = "offline"
                            print("must login first")
                        booler = False
                    except:
                        pass
            elif mType == "subscribe" and status == "offline":
                print("not logged in")
            elif mType == "unsubscribe" and status == "online":
                packet = {"MAGIC_1": MAGIC_1, "MAGIC_2": MAGIC_2, "mType": "unsubscribe", "token": token, "payload": f.encrypt(payload)}
                ret = sock.sendto(pickle.dumps(packet), ('3.16.183.65', 10020))
                booler = True
                while (booler):
                    try:
                        data, server = sock.recvfrom(4096)
                        rawData = pickle.loads(data)
                        if rawData["mType"] == "unsubscribe#ack":
                            print("unsubscribe#ack")
                        elif rawData["mType"] == "unsubscribe#fail":
                            print("unsubscribe#failure")
                        elif rawData["mType"] == "session#timeout":
                            status = "offline"
                            print("must login first")
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
                ret = sock.sendto(pickle.dumps(packet), ('3.16.183.65', 10020))
                booler = True
                while (booler):
                    try:
                        data, server = sock.recvfrom(4096)
                        rawData = pickle.loads(data)
                        if rawData["mType"] == "retrieve#ack":

                            print(f.decrypt(rawData["payload"]))

                        elif rawData["mType"] == "retrieve#fail":
                            print("retrieve#failure")
                        elif rawData["mType"] == "session#timeout":
                            status = "offline"
                            print("must log in first")
                        booler = False
                    except:
                        pass
            elif mType == "retrieve" and status == "offline":
                print("not logged in")
            elif mType == "spurious" and status == "online":
                packet = {"MAGIC_1": MAGIC_1, "MAGIC_2": MAGIC_2, "mType": "spurious", "token": token, "payload": f.encrypt(payload)}
                ret = sock.sendto(pickle.dumps(packet), ('3.16.183.65', 10020))
                booler = True
                while (booler):
                    try:
                        data, server = sock.recvfrom(4096)
                        rawData = pickle.loads(data)
                        if rawData["mType"] == "spurious#ack":
                            print("okay")
                        elif rawData["mType"] == "session#reset":
                            print("Error occurred session has been reset by server.")
                            status = "offline"
                        booler = False
                    except:
                        pass
            elif mType == "serverSpur" and status == "online":
                packet = {"MAGIC_1": MAGIC_1, "MAGIC_2": MAGIC_2, "mType": "serverSpur", "token": token,
                          "payload": None}
                ret = sock.sendto(pickle.dumps(packet), ('3.16.183.65', 10020))
                booler = True
            elif mType == "upload" and status == "online":
                packet = {"MAGIC_1": MAGIC_1, "MAGIC_2": MAGIC_2, "mType": "upload", "token": token,
                          "payload": f.encrypt(payload)}
                ret = sock.sendto(pickle.dumps(packet), ('3.16.183.65', 10020))
                __location__ = os.path.realpath(
                    os.path.join(os.getcwd(), os.path.dirname(__file__)))
                file = open(os.path.join(__location__, payload), "rb");
                data = file.read(1024)
                while(data):
                    if(sock.sendto(f.encrypt(data), ('3.16.183.65', 10020))):
                        data = file.read(1024)
                file.close()
            uInput = None
        else:
            try:
                data, server = sock.recvfrom(4096)
                rawData = pickle.loads(data)
                if rawData["mType"] == "retrieve#ack":
                    print(f.decrypt(rawData["payload"]))
                elif rawData["mType"] == "forward#message":
                    print(f.decrypt(rawData["payload"]))
                elif rawData["mType"] == "forward#fail":
                    print("forwarding#failure")
                elif rawData["mType"] == "session#reset":
                    print("Session reset triggered by server")
                    status = "offline"
                elif rawData["mType"] == "session#timeout":
                    print("timeout happened")
                    status = "offline"
                elif rawData["mType"] == "file#forward":
                    __location__ = os.path.realpath(
                        os.path.join(os.getcwd(), os.path.dirname(__file__)))
                    file = open(os.path.join(__location__, "dsy" + f.decrypt(rawData["payload"])), 'wb')

                    booler = True
                    while (booler):
                        try:
                            print("in here")
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
                    file.close()
                else:
                    print(rawData)
                    packet = {"MAGIC_1": MAGIC_1, "MAGIC_2": MAGIC_2, "mType": "serverReset", "token": token,
                              "payload": None}
                    ret = sock.sendto(pickle.dumps(packet), ('3.16.183.65', 10020))
                    status = "offline"
                    print("Session reset triggered by client")


            except:
                pass


t = threading.Thread(target=main)
t.daemon = True
t.start()

while True:
    global uInput
    uInput = raw_input("")


