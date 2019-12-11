import socket
import time
import pickle
import random
import os
import threading
from Crypto.Util import number
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
import hmac
import hashlib
import base64
from collections import defaultdict
global userInput
MAGIC_1 = 'A'
MAGIC_2 = 'K'
MAGIC_2 = 'K'
clients = {}
info1 = {"password": "lu", "address": None, "status": "offline", "token": None, "subscriptions": [], "posts": [], "time": None}
clients["duo"]=info1
info2 = {"password": "kappa", "address": None, "status": "offline", "token": None, "subscriptions": [], "posts": [], "time": None}
clients["muffles"] = info2
info2 = {"password": "password", "address": None, "status": "offline", "token": None, "subscriptions": [], "posts": [], "time": None}
clients["ken"] = info2
tokens = {}
keyDict = {}

def generate_partial_key(Pkey1, Pkey2, Prkey1):
    partial_key = Pkey1 ** Prkey1
    partial_key = partial_key % Pkey2
    return partial_key

def generate_full_key(partial_key_r, PrKey1, PKey2):
    full_key = partial_key_r ** PrKey1
    full_key = full_key % PKey2
    full_key = full_key
    return full_key



def checkTime():
    while(True):
        for key in clients:
            if clients[key]["time"] != None and clients[key]["time"] != "nope" and time.time()-clients[key]["time"] > 60:
                clients[key]["time"] = "nope"
                clients[key]["status"] = "offline"


t = threading.Thread(target=checkTime)
t.daemon = True
t.start()
while True:
    print("goin")
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind(('localhost', 10020))
    print("receicing")
    data, address = sock.recvfrom(4096)
    rawData = pickle.loads(data)
    sent = False
    timeBool = False
    currKey = None
    for client in keyDict:
        if client == address:
            currKey = keyDict[client]
            f = Fernet(currKey)
    full_key = None
    Hprivate = number.getPrime(16)
    Hpublic = number.getPrime(16)
    Cpublic = None
    Cpartial = None
    Hpartial = None
    for client in clients:
        if rawData["mType"] in {"subscribe", "unsubscribe", "retrieve", "post"} and rawData["token"] == clients[client]["token"] and clients[client]["time"] == "nope":
            packet = {"MAGIC_1": MAGIC_1, "MAGIC_2": MAGIC_2, "mType": "session#timeout",
                      "token": clients[key]["token"], "payload": None}
            clients[key]["status"] = "offline"
            ret = sock.sendto(pickle.dumps(packet), address)
            timeBool = True
    if timeBool:
        continue

    if rawData["mType"] == "getPublicKey":
        Cpublic = int(rawData["payload"])
        packet = {"MAGIC_1": MAGIC_1, "MAGIC_2": MAGIC_2, "mType": "gotPublicKey", "token": None, "payload": Hpublic}
        ret = sock.sendto(pickle.dumps(packet), address)

        booler = True
        while (booler):
            try:
                data, address = sock.recvfrom(4096)
                rawData = pickle.loads(data)
                booler = False
            except:
                pass
        Cpartial = int(rawData["payload"])
        Hpartial = generate_partial_key(Cpublic, Hpublic, Hprivate)
        packet = {"MAGIC_1": MAGIC_1, "MAGIC_2": MAGIC_2, "mType": "gotPartial", "token": None, "payload": Hpartial}
        ret = sock.sendto(pickle.dumps(packet), address)
        full_key = generate_full_key(Cpartial, Hprivate, Hpublic)



        print(full_key)
        salt = b'salt_'
        full_key_encode = str(full_key).encode()
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
        keyDict[address] = key

    elif rawData["mType"] == "login":
        username, password = f.decrypt(rawData["payload"]).split("&")
        for key in clients:
            print(username)
            print(key)
            if key == username:
                print("match")
                if clients[key]["password"] == password and clients[key]["status"] == "offline":
                    print(clients[key]["password"])
                    checker = True
                    token = random.getrandbits(32)
                    while (checker):
                        checker = False
                        for client in clients:
                            if token == clients[client]["token"]:
                                token = random.getrandbits(32)
                                checker = True
                    clients[key]["token"] = token
                    packet = {"MAGIC_1": MAGIC_1, "MAGIC_2": MAGIC_2, "mType": "login_success", "token": clients[key]["token"], "payload": None}
                    clients[key]["status"] = "online"
                    clients[key]["address"] = address
                    print("sending")
                    clients[key]["time"] = time.time()
                    ret = sock.sendto(pickle.dumps(packet), address)
                    sent = True

        if not sent:
            print("notsent")
            packet = {"MAGIC_1": MAGIC_1, "MAGIC_2": MAGIC_2, "mType": "login_fail", "token": clients[key]["token"],
                      "payload": None}
            ret = sock.sendto(pickle.dumps(packet), address)
    elif rawData["mType"] == "post":
        sent = False
        for key in clients:
            if clients[key]["token"] == rawData["token"] and clients[key]["status"] == "online":
                clients[key]["time"] = time.time()
                for client in clients:
                    for sub in clients[client]["subscriptions"]:
                        if sub == key and clients[client]["status"] == "online":
                            print("sending to")
                            print(sub)
                            print(clients[client]["address"])
                            sendmsg="<{}> {}".format(key, f.decrypt(rawData["payload"]))
                            for hashKey in keyDict:
                                if hashKey == clients[client]["address"]:
                                    currKey = keyDict[hashKey]
                                    f1 = Fernet(currKey)
                            packet = {"MAGIC_1": MAGIC_1, "MAGIC_2": MAGIC_2, "mType": "forward#message",
                                      "token": clients[key]["token"], "payload": f1.encrypt(sendmsg)}
                            clients[client]["time"] = time.time()
                            print("sent once")
                            ret = sock.sendto(pickle.dumps(packet), clients[client]["address"])
                clients[key]["posts"].append("<{}> {}".format(key, f.decrypt(rawData["payload"])))
                print(clients[key]["posts"])


                packet = {"MAGIC_1": MAGIC_1, "MAGIC_2": MAGIC_2, "mType": "post#ack",
                      "token": clients[key]["token"], "payload": None}

                ret = sock.sendto(pickle.dumps(packet), clients[key]["address"])
                sent = True
        if not sent:
            packet = {"MAGIC_1": MAGIC_1, "MAGIC_2": MAGIC_2, "mType": "post#fail",
                      "token": clients[key]["token"], "payload": None}
            ret = sock.sendto(pickle.dumps(packet), address)

    elif rawData["mType"] == "logout":
        sent = False
        for key in clients:
            if clients[key]["token"] == rawData["token"] and clients[key]["status"] == "online":
                clients[key]["time"] = time.time()
                clients[key]["status"] = "offline"
                clients[key]["token"] = None
                packet = {"MAGIC_1": MAGIC_1, "MAGIC_2": MAGIC_2, "mType": "logout#ack",
                          "token": clients[key]["token"], "payload": None}
                ret = sock.sendto(pickle.dumps(packet), address)
                sent=True
        if not sent:
            packet = {"MAGIC_1": MAGIC_1, "MAGIC_2": MAGIC_2, "mType": "logout#fail",
                      "token": clients[key]["token"], "payload": None}
            ret = sock.sendto(pickle.dumps(packet), address)

    elif rawData["mType"] == "subscribe":
        sent = False
        for key in clients:
            if clients[key]["token"] == rawData["token"] and clients[key]["status"] == "online":
                clients[key]["time"] = time.time()
                print("tokens and status match")
                for client in clients:
                    print("paylod is")
                    print(rawData["payload"])
                    print(client)
                    if client == f.decrypt(rawData["payload"]):
                        clients[key]["subscriptions"].append(f.decrypt(rawData["payload"]))
                        print(clients[key]["subscriptions"])
                        packet = {"MAGIC_1": MAGIC_1, "MAGIC_2": MAGIC_2, "mType": "subscribe#ack",
                                  "token": clients[key]["token"], "payload": None}
                        ret = sock.sendto(pickle.dumps(packet), address)
                        sent = True
                        print("sent")
        if not sent:
            packet = {"MAGIC_1": MAGIC_1, "MAGIC_2": MAGIC_2, "mType": "subscribe#fail",
                      "token": clients[key]["token"], "payload": None}
            ret = sock.sendto(pickle.dumps(packet), address)

    elif rawData["mType"] == "unsubscribe":
        sent = False
        for key in clients:
            if clients[key]["token"] == rawData["token"] and clients[key]["status"] == "online":
                clients[key]["time"] = time.time()
                for client in clients:
                    if client == f.decrypt(rawData["payload"]):
                        try:
                            clients[key]["subscriptions"].remove(f.decrypt(rawData["payload"]))
                        except ValueError:
                            pass
                        packet = {"MAGIC_1": MAGIC_1, "MAGIC_2": MAGIC_2, "mType": "unsubscribe#ack",
                                  "token": clients[key]["token"], "payload": None}
                        ret = sock.sendto(pickle.dumps(packet), address)
                        sent = True
        if not sent:
            packet = {"MAGIC_1": MAGIC_1, "MAGIC_2": MAGIC_2, "mType": "unsubscribe#fail",
                      "token": clients[key]["token"], "payload": None}
            ret = sock.sendto(pickle.dumps(packet), address)
    elif rawData["mType"] == "retrieve":
        print("here")
        sent = False
        for key in clients:
            if clients[key]["token"] == rawData["token"] and clients[key]["status"] == "online":
                clients[key]["time"] = time.time()
                print(clients[key]["subscriptions"])
                for sub in clients[key]["subscriptions"]:

                    i = 1
                    n = int(f.decrypt(rawData["payload"]))
                    print(sub)
                    print(i)
                    print(n)
                    for post in clients[sub]["posts"]:
                        print(post)
                        if i > n:
                            break
                        else:

                            packet = {"MAGIC_1": MAGIC_1, "MAGIC_2": MAGIC_2, "mType": "retrieve#ack",
                                      "token": clients[key]["token"], "payload": f.encrypt(post)}
                            ret = sock.sendto(pickle.dumps(packet), address)
                            print("sent")
                            print(post)
                            i += 1
                sent = True
        if not sent:
            packet = {"MAGIC_1": MAGIC_1, "MAGIC_2": MAGIC_2, "mType": "retrieve#fail",
                      "token": clients[key]["token"], "payload": None}
            ret = sock.sendto(pickle.dumps(packet), address)
    elif rawData["mType"] == "serverSpur":
        packet = {"MAGIC_1": MAGIC_1, "MAGIC_2": MAGIC_2, "mType": "serverSpur",
                  "token": clients[key]["token"], "payload": None}
        ret = sock.sendto(pickle.dumps(packet), address)
    elif rawData["mType"] == "serverReset":
        for key in clients:
            if clients[key]["token"] == rawData["token"] and clients[key]["status"] == "online":
                clients[key]["status"] = "offline"
                clients[key]["token"] = None
    elif rawData["mType"] == "upload":
        for key in clients:
            if clients[key]["token"] == rawData["token"] and clients[key]["status"] == "online":
                __location__ = os.path.realpath(
                    os.path.join(os.getcwd(), os.path.dirname(__file__)))
                file = open(os.path.join(__location__, "cpy" + f.decrypt(rawData["payload"])), 'wb')


                booler = True
                while (booler):
                    try:
                        data, address = sock.recvfrom(4096)
                        print(f.decrypt)
                        booler= False
                    except:
                        pass
                try:
                    while(data):
                        print("getting file")
                        file.write(f.decrypt(data))
                        sock.settimeout(2)
                        data, address = sock.recvfrom(4096)
                except:
                    pass
                file.close()
                clients[key]["time"] = time.time()
                for client in clients:
                    for sub in clients[client]["subscriptions"]:
                        if sub == key and clients[client]["status"] == "online":
                            print("sending to")
                            print(sub)
                            print(clients[client]["address"])
                            for hashKey in keyDict:
                                if hashKey == clients[client]["address"]:
                                    currKey = keyDict[hashKey]
                                    f1 = Fernet(currKey)
                            packet = {"MAGIC_1": MAGIC_1, "MAGIC_2": MAGIC_2, "mType": "file#forward", "token": token,
                                      "payload": f1.encrypt(f.decrypt(rawData["payload"]))}

                            ret = sock.sendto(pickle.dumps(packet), clients[client]["address"])

                            __location__ = os.path.realpath(
                                os.path.join(os.getcwd(), os.path.dirname(__file__)))
                            file = open(os.path.join(__location__, "cpy" + f.decrypt(rawData["payload"])), "rb");
                            data = file.read(1024)
                            while (data):
                                print("theres data and we send")
                                if (sock.sendto(f1.encrypt(data), clients[client]["address"])):
                                    data = file.read(1024)
                            file.close()





    else:
        for key in clients:
            if clients[key]["token"] == rawData["token"] and clients[key]["status"] == "online":
                clients[key]["status"] = "offline"
                clients[key]["token"] = None
        packet = {"MAGIC_1": MAGIC_1, "MAGIC_2": MAGIC_2, "mType": "session#reset",
                  "token": clients[key]["token"], "payload": None}
        ret = sock.sendto(pickle.dumps(packet), address)