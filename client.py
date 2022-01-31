from io import TextIOWrapper
import ipaddress
import math
import select
import sys
from warnings import catch_warnings
import anytree
from ecdsa.ecdsa import Public_key
import requests
import urllib3
import socket
import numpy as np
import bitarray as bit
import time
import ecdsa
import hashlib
import os
import merkle
import random
import threading
import errno
import struct
import shlex
from bitarray.util import ba2int
from bitarray.util import int2ba
from anytree import Node, RenderTree, render
from ipaddress import ip_address, IPv4Address, IPv6Address


# clefs cryptographique
privateKey = ecdsa.SigningKey.generate(curve=ecdsa.SECP256k1, hashfunc=hashlib.sha256)
publicKey  = privateKey.get_verifying_key()


URL = "https://jch.irif.fr:8082/"
NAME = "ChristianMika"
SERVER_PEER = "jch.irif.fr"
#addresse (hote, port) qu on veut utiliser
MY_ADDR = [
    #('192.168.1.24', 10009)
]
DEFAULT_PORT = 10009

#Mettre l arborescence des fichiers qu on veut exporter
MY_TREE = "peers/ChristianMika"

#active le mode signature, il est un peu buggé, son server ne supporte pas la crypto
SIGNATURE = False
#active le mode racine
ROOT = True
#active le mode debug
DEBUG = True
  #Genere des nombres aléatoire à une limite de :
MAX_RAND = 1000000000
DEFAULT_WINDOWS = 50
#les extensions que notre client supporte actuellement
extensions_bit = bit.bitarray('00000000000000000000000010001101', endian='big')

types = {
    "Hello"                 : 0,
    "PublicKey"             : 1,
    "Root"                  : 2,
    "GetDatum"              : 3,

    "HelloReply"            : 128,
    "PublicKeyReply"        : 129,
    "RootReply"             : 130,
    "Datum"                 : 131,
    "NoDatum"               : 132,
    "NatTraversalRequest"   : 133,
    "NatTraversal"          : 134,

    "Error"                 : 254
}
types_name = {
    0   : "Hello",
    1   : "PublicKey",
    2   : "Root",  
    3   : "GetDatum",

    128 : "HelloReply",
    129 : "PublicKeyReply",
    130 : "RootReply",
    131 : "Datum",
    132 : "NoDatum",
    133 : "NatTraversalRequest",
    134 : "NatTraversal",

    254 : "Error"
}

# { (ip,port) : (name, key, root) }
peers         = {}
# { (ip,port) : time              }
addr_answer_t = {}
# { name      : list((ip, port))  }
peers_addr    = {}
# { name      : time              }
peer_answer_t = {}
# { name      : time              }
time_send     = {}
# { name      : (win, vol)        }
peer_windows  = {}
# { name      : Node(name, dict("type", "hash"))}
peers_tree    = {}
#les extensions de nos pairs { name : bitarray() }
peers_ext     = {}
# { name      : list( (msg, id, interval, times, timestamp, check) )}
pending_msg   = {}


#parametrage head pour request.get
head={"User-Agent": "Mozilla/5.0 (X11; CrOS x86_64 12871.102.0) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/81.0.4044.141 Safari/537.36"}

state={
    "update" : True,
    "processing" : False,
    "root"       : merkle.updateRoot(),
    "root_modified" : False
}

sock_lst = []

LINES, NUM = 0, 1
log_file = {
    LINES : 0,
    NUM   : 0
}

# Permet d ecrire le debuging dans un fichier log, 
# si il y a plus de 500 entree, il creer un autre fichier et ecrit dessus
def writeLog(msg):
    with open("./log"+str(log_file[NUM]), "a+") as f :
        f.write(msg+"\n")
        log_file[LINES]+=1
    if log_file[LINES]>500 : 
        log_file[NUM]+=1
        log_file[LINES]=0

# Debug des requests
def request_log(): 
    import logging
    import http.client
    http.client.HTTPConnection.debuglevel = 1
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    logging.basicConfig()
    logging.getLogger().setLevel(logging.DEBUG)
    requests_log = logging.getLogger("requests.packages.urllib3")
    requests_log.setLevel(logging.DEBUG)
    requests_log.propagate = True

# Methode permettant d obtenir automatiquement l IPV4 du client
def getlocalIPV4():
    try : 
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        (ip, port) = s.getsockname()
        s.close()
        return ip
    except : 
        return None

# Idem mais en IPV6
def getpublicIPV6() : 
    try :
        server_r = requests.get(url="https://api6.ipify.org/", headers=head, timeout=5)
        return server_r.text
    except : 
        return None

# transforme un IP4 en IP6 mapped
def ip4to6(ip:str):
    numbers = list(map(int, ip.split('.')))
    ip6 = '2002:{:02x}{:02x}:{:02x}{:02x}::'.format(*numbers)
    return ip6

# verifie si c est un IPV4
def isIpv4(ip:str):
    try : 
        socket.inet_aton(ip)
        return True
    except : 
        return False

# Transforme un IP4 mapped en IP4, si l addresse est un IPV6 => bool, renvoit IPV6
def mapped_to_IP4(ip:str): 
    ip6 = ipaddress.ip_address(ip)
    ip6_split = ip6.exploded.split(":")
    for i in range(3, len(ip6_split)-1):
        if ip6_split[i]!='0000' : return False, ip
    num = ip6_split[1]+ip6_split[2]
    return True, ".".join([ str(int(num[i:i+2], 16)) for i in range(0, len(num), 2)])

# Selectionne un socket appropriee en fonction de l IP 
def selectSocket(ip:str) : 
    if ip is None : return None
    if isIpv4(ip) : 
        family = socket.AF_INET
    else : family = socket.AF_INET6
    for sock in sock_lst : 
        if sock.family == family : return sock
    return None


#creer un socket
def create_socket(addr_lst) : 
    for (ip, port) in addr_lst : 
        if isIpv4(ip) : 
            my_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
        else : 
            my_sock = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
        my_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        my_sock.setblocking(False)
        my_sock.bind( (ip, port) )
        sock_lst.append(my_sock)



# converti les bitarray de taille<32 en bit de taille 32, 110 ---> 0000...0110
def bit32(bits) : 
    mask = bit.bitarray(32)
    mask.setall(0)
    decalage = len(mask)-len(bits)
    for i, e in enumerate(bits) : 
        mask[i+decalage] = e
    return mask

# Return IP, PORT
def split_ip_port(addresse) : 
    addr = addresse.rsplit(':', 1)
    return addr[0].strip(']['), int(addr[1])

# retourne la version longue de ip
def explode_ip(ip) : 
    if type(ip_address(ip)) is not IPv4Address : 
        return ipaddress.ip_address(ip).exploded
    else : return ip


def update_time(name) : 
    time_tmp = time.time()
    if name not in time_send     : time_send[name]     = time_tmp-100
    if name not in peer_answer_t : peer_answer_t[name] = time_tmp-100
    for addr in peers_addr[name] : 
        if addr not in addr_answer_t : addr_answer_t[addr] = time_tmp-100

def delete_peers(names):
    if DEBUG and names: writeLog("[notice] logged out peers" + str(names))
    for name in names : 
        time_send.pop    (name, None)       #1
        peer_answer_t.pop(name, None)       #2
        for addr in peers_addr[name] :
            peers.pop        (addr, None)   #3
            addr_answer_t.pop(addr, None)   #4
        peers_addr.pop   (name, None)       #5
        peers_tree.pop   (name, None)       #6
        peer_windows.pop (name, None)       #7
        pending_msg.pop  (name, None)       #8

# Met a jour nle root du pair name
def update_root(name : str, hash : bytes) : 
    if not hash : return
    if name not in peers_tree.keys() : 
        peers_tree[name] = Node(name, kwargs={"type" : 4, "hash" : hash})
    else : 
        node:Node = peers_tree[name]
        if node.__dict__['kwargs']["hash"]!=hash : 
            node = {"type" : 4, "hash" : hash}
            writeLog("[notice] "+name+" modified his root")
    return

# Met a jour les donnees recus du server
def update_peers(server_url, printer=False) : 
    try :
        server_r = requests.get(url=server_url+'peers/', headers=head, timeout=5)
        pairs_names = server_r.text.splitlines()
        valid_pair_name = []
        for name in pairs_names : 
            #if name != SERVER_PEER : continue
            if name == NAME : continue
            if printer : print(name, pairs_names)
            try : 
                peer_r = requests.get(url=server_url+'peers/'+name+'/addresses', headers=head, timeout=10)
                key_r = requests.get(url=server_url+'peers/'+name+'/key', headers=head, stream=True, timeout=10)
                hash_r = requests.get(url=server_url+'peers/'+name+'/root', headers=head, stream=True, timeout=10)
            except : 
                print("Couldn't fetch", name)
                continue
            while state["processing"] : time.sleep(0.01)
            state["update"]=True
            if peer_r.ok and key_r.ok and hash_r.ok : 
                ip_lst, key, hash = peer_r.text.splitlines(), key_r.content, hash_r.content
                if not ip_lst : continue #Si le pair n a pas de ip, on l ajoute pas
                addr_lst = []
                for addr in ip_lst :
                    ip,port    = split_ip_port(addr)
                    ip = explode_ip(ip)
                    addr_lst.append(  (ip,port)  )
                    peers[(ip,port)]  = (name, key, hash)
                peers_addr[name] = addr_lst
                valid_pair_name.append(name)
                if name not in peer_windows.keys() : peer_windows[name]=(DEFAULT_WINDOWS, 0)
                if name not in pending_msg.keys()  : pending_msg [name]=[]
                update_time(name)
                update_root(name, hash)
            state["update"]=False
        while state["processing"]: time.sleep(0.01)
        state["update"]=True
        delete_peers(set(peers_addr.keys())-set(valid_pair_name))
        state["update"]=False
    except Exception as e: 
        writeLog("[error]"+server_url+ "unavailable :"+ str(e))





# args : int, int, int, bytearray, string -> bytearray
def encode_message(id:int, type:int, length:int, body:bytearray, signature:bool)->bytearray : 
    message     = bytearray()
    message    += id.to_bytes    (4, 'big')
    message    += type.to_bytes  (1, 'big')
    message    += length.to_bytes(2, 'big')
    message    += bytes(body)
    if signature == True : 
        sign = privateKey.sign(bytes(message))
        message    += sign
    return message

# Creer un message hello comme convenu dans le protocol: 
# args : int, int, string -> bytearray
def encode_hello(id:int, type:int, name:str)->bytearray : 
    body, extension, length = bytearray(), ba2int(extensions_bit), len(name)+4
    body += extension.to_bytes(4, 'big')
    body += bytearray(name.encode())
    return encode_message(id, type, length, body, SIGNATURE)

def encode_hello_message(id, name)      : return encode_hello(id, types['Hello']     , name)
def encode_helloReply_message(id, name) : return encode_hello(id, types['HelloReply'], name)

def encode_publicKey(id:int, type:int)->bytearray: 
    if SIGNATURE == False : return encode_message(id, type, 0, bytearray(), SIGNATURE)
    body, length = bytearray(), 64
    body += publicKey.to_string()
    return encode_message(id, type, length, body, SIGNATURE)

def encode_root(id:int, type:int)->bytearray: 
    root:Node = state["root"]
    if ROOT : return encode_message(id, type, len(root.name), root.name, SIGNATURE)
    else :    return encode_message(id, type, 0, b'', SIGNATURE)

def encode_getDatum(id:int, hash:bytes)->bytearray:
    body, length = bytearray(), 32
    body += hash
    return encode_message(id, types['GetDatum'], length, body, False)

def encode_noDatum(id:int, hash:bytes)->bytearray:
    body, length = bytearray(), 32
    body += hash
    return encode_message(id, types["NoDatum"], length, body, False)

def encode_datum(id:int, hash:bytes, data:bytes) : 
    body   = bytearray()
    length = len(data)+len(hash)
    body += hash
    body += data
    return encode_message(id, types["Datum"], length, body, False)

def encode_chunk_datum(id:int, hash:bytes, data:bytes)->bytearray : 
    body  = bytearray()
    body += hash
    body += merkle.type_bytes[merkle.CHUNK]
    body += data
    length = len(body)
    return encode_message(id, types['Datum'], length, body, False)

def encode_tree_datum(id:int, hash:bytes, list)->bytearray : 
    body  = bytearray()
    body += hash
    body += merkle.type_bytes[merkle.TREE]
    for h in list : body += h
    length = len(body)
    return encode_message(id, types['Datum'], length, body, False)

def encode_dir_datum(id:int, hash:bytes, list)->bytearray :
    body  = bytearray()
    body += hash
    body += merkle.type_bytes[merkle.DIR]
    for (name, h) in list : 
        body += name.encode()
        body += h
    length = len(body)
    return encode_message(id, types['Datum'], length, body, False)

def encode_NatTraversalRequest(id:int, addr):
    body = bytearray()
    if isIpv4(addr[0]) : 
        m_addr = (ip4to6(addr[0]), addr[1])
    else : 
        m_addr = addr
    (ip, port) = m_addr
    body += socket.inet_pton(socket.AF_INET6, ip)
    body += int(port).to_bytes(2 , 'big')
    return encode_message(id, types["NatTraversalRequest"], 18, body, False)



def encode_error(id:int, message:str) : 
    body = bytearray()
    body+=message.encode()
    return encode_message(id, types["Error"], len(message), body, False)


def decode_dir (msg) :
    lst = []
    for i in range(len(msg)//64) :
        start = i*64
        end = (i+1)*64 
        name = msg[start:(start+end)//2].decode()
        hash = msg[(start+end)//2:end]
        data = name, hash
        lst.append(data)
    return lst

def decode_tree(msg) :
    hash_list = []
    for i in range (len(msg)//32) : 
        start = i*32
        end   = (i+1)*32
        hash = msg[start:end]
        hash_list.append(hash)
    return hash_list


def decode_chunk(msg) : 
    return msg

# hash, type, data
def decode_datum(msg) : 
    hash      = msg[0:32]
    type      = int.from_bytes(msg[32:33], byteorder='big', signed=False)
    if type == merkle.CHUNK : 
        return hash, type, decode_chunk(msg[33:len(msg)])
    elif type == merkle.TREE : 
        return hash, type, decode_tree(msg[33:len(msg)])
    elif type == merkle.DIR : 
        return hash, type, decode_dir (msg[33:len(msg)])
    return msg

# decode le corps du message : 
# args : bytes, int, int -> any (en fonction du protocole)
def decode_body(msg, type:bytes, length): 
    if   type == types['Hello']  or type == types['HelloReply']: 
        extensions  = bit32(int2ba(int.from_bytes(msg[0:4], byteorder='big', signed=False)))
        name        = msg[4:length].decode()
        return (extensions, name)
    elif type == types['PublicKey'] or type == types['PublicKeyReply'] : 
        key = msg
        return key
    elif type == types['Root'] or type == types['RootReply'] :
        return msg
    elif type == types['Datum'] : 
        return decode_datum(msg) 
    elif type == types['GetDatum'] : 
        return msg 
    elif type == types['NoDatum'] :
        return msg
    elif type == types["NatTraversal"] : 
        m_ip = socket.inet_ntop(socket.AF_INET6, msg[0:16])
        isIPV4, ip = mapped_to_IP4(m_ip)
        port = int.from_bytes(msg[16:18], byteorder='big', signed=False)
        return (ip,port)
    elif type == types["NatTraversalRequest"] : 
        m_ip = socket.inet_ntop(socket.AF_INET6, msg[0:16])
        isIPV4, ip = mapped_to_IP4(m_ip)
        port = int.from_bytes(msg[16:18], byteorder='big', signed=False)
        return (ip,port)
    elif type == types['Error'] :
        return msg
    else : 
        writeLog("[unexpected]received an unexpected type :"+ int.from_bytes(type, "big"))
        return msg

# decode un message :
# args : bytes -> (int, int, int, any, string)
def decode_message(msg, printer=False) : 
    id        = int.from_bytes(msg[0:4], byteorder='big', signed=False)
    type      = int.from_bytes(msg[4:5], byteorder='big', signed=False)
    length    = int.from_bytes(msg[5:7], byteorder='big', signed=False)
    body      = decode_body(msg[7:length+7], type, length)
    signature = msg[7+length:len(msg)]
    if printer : type = types_name[type]
    return (id, type, length, body, signature)

def sendAll(sock, msg, addr_list) : 
    if len(addr_list) == 0 : return False
    try : 
        sock.sendto(msg, addr_list[0])
        name =  peers[ addr_list[0] ][0]
        time_send[ name  ] = time.time() 
        if DEBUG : writeLog(">>>"+str(name)+"\t"+str(addr_list[0])+"\n\t"+ str(decode_message(msg, True))) 
        return True

    except Exception as e:
        return sendAll(sock, msg, addr_list[1:])


def send(sock, msg, addr) :
    try :
        sock.sendto(msg, addr)
        name = peers[addr][0]
        time_send[  name  ] = time.time() 
        if DEBUG : writeLog(">>>"+ name + "\t"+str(addr)+ "\n\t"+ str(decode_message(msg, True))) 
        return True
    except Exception as e:
        print(e)
        #name = peers[addr][0]
        #if sendAll(sock, msg, peers_addr[name]) == False :  
        #    if DEBUG : 
        #        writeLog("[error]"+name+" is unreachable")
        #        #relance dans quelques secondes
        #        time_send[name] = time.time()+15
        #        return False
        return False


def latest_answer_addr_or_random(addr_lst, name, limit) :
    if bool(peer_answer_t[name]) : 
        time_tmp = time.time()
        if(len(addr_lst) == 0) : 
            writeLog("[error]"+name, "has no compatible ip")
            writeLog(str(peers_addr[name]))
            return None
        min_t, min_addr = addr_answer_t[addr_lst[0]], addr_lst[0]
        for addr in addr_lst : 
            if time_tmp - addr_answer_t[addr] < time_tmp - min_t :
                min_t, min_addr = addr_answer_t[addr], addr
        if min_t<limit : 
            return random.choice(addr_lst)
        return min_addr
    else : return random.choice(addr_lst)
    
def allEqual_time(addr_lst):
    if len(addr_lst)<2 : return True
    times =  [addr_answer_t[x] for x in addr_lst]
    return all( times[0] == x for x in times)
    
# envoie un message hello à tous les pairs connu, 
# si un pair n'a pas envoyé de message entre [30,45] secondes, le client envoit un message sur la dernière addresse ou un message a été reçue
# si un pair n'a pas envoyé de message entre [45,60] secondes, le client envoit un message suur une addresse aléatoire du peer 
# si un pair n'a pas envoyé de message plus de 60 secondes, le client envoit un message à toute les addresse du peer
def keep_register(): 
    for name in peers_addr.keys() : 
        if name != SERVER_PEER : continue
        if not pending_msg[name] : 
            timestamp = (time.time() - time_send[name])
            if(name not in time_send) or (timestamp > 30) :
                id = random.randint(1,MAX_RAND) 
                hello_msg = bytes( encode_hello_message(id, NAME) )
                if allEqual_time(  list( set(addr_answer_t.keys()) &  set(peers_addr[name]) )    ) : 
                    addr_lst = peers_addr[name]
                    for addr in addr_lst :  
                        send_notExpectedReply(hello_msg, addr, name, id, interval=30, times=3)
                else :
                    addr = latest_answer_addr_or_random(compatible_addr(name), name, 45)
                    send_notExpectedReply(hello_msg, addr, name, id, interval=30, times=3)


def findPere(name, hash, type) : 
    pere : Node  = anytree.search.find(peers_tree[name], lambda node: node.__dict__['kwargs']["hash"]==hash )
    if pere is None and type == merkle.DIR: return None 
    if pere is not None : return pere
    else : 
        pere_lst = anytree.search.findall(peers_tree[name], lambda node: node.__dict__['kwargs']["type"]==merkle.TREE  )
        for node in pere_lst : 
            if "hash_chunk" in node.__dict__['kwargs']["hash_chunk"] and hash in node.__dict__['kwargs']["hash_chunk"] : 
                pere = node 
                break
        return pere


def queue_send(msg, name, id, interval, times, check):
    pending_msg[name].append( (msg, id, interval, times, time.time(), check) )

def queue_remove(id, name):
    ret = False
    #n=0
    for data in pending_msg[name] : 
        (m_msg, m_id,  m_interval, m_times, m_stmp, m_check)=data
        if m_id==id:
            if m_check :
                win, vol = peer_windows[name] 
                peer_windows[name] = (win+1, vol-1)
            pending_msg[name].remove(data)
            ret = True
            #n+=1
    #print("Removed : ", n, "id=", id)
    return ret

def compatible_addr(name) : 
    addr_lst = []
    for (ip, port) in peers_addr[name] : 
        if selectSocket(ip) is not None : 
            addr_lst.append( (ip, port) )
    return addr_lst


def apply_queue():
    for name in pending_msg.keys() : 
        for i,data in enumerate(pending_msg[name]) : 
            (msg, id,  interval, times, stmp, check)=data
            if time.time() > stmp+interval : 
                if times <=0 : pending_msg[name].remove(data)
                else : 
                    (win, vol) = peer_windows[name]
                    if vol < win or (not check): 
                        addr = latest_answer_addr_or_random(compatible_addr(name), name, 2)
                        sock = selectSocket(addr[0])
                        if sock is not None :
                            if send(sock, msg, addr): 
                                pending_msg[name][i] = (msg, id, interval, times-1, time.time(), check)
                                if check : peer_windows[name] = (math.ceil(win/2), vol+1)
                            else : #Cas o`u c'est nous qui arrivons pas à envoyer`
                                pending_msg[name][i] = (msg, id, 30, times, time.time(), check)
                    else : ""

def send_by_windows(sock:socket, msg, addr, name, id, interval, times, check):
    (win, vol) = peer_windows[name]
    t = times
    if vol < win or (not check): 
        if send(sock, msg, addr) :
            if check : peer_windows[name] = win,(vol+1)
            t-=1
    if t>0 : queue_send(msg, name, id, interval, t, check)

def send_notExpectedReply(msg, addr, name, id, interval=3, times=3) : 
    sock = selectSocket(addr[0])
    if sock is not None :
        send_by_windows(sock, msg, addr, name, id, interval, times, False)

def send_ExpectedReply(msg, addr, name, id, interval=5, times=3):
    sock = selectSocket(addr[0])
    if sock is not None :
        send_by_windows(sock, msg, addr, name, id, interval, times, True)


def has_pending_id(id, name):
    for msg in pending_msg[name] : 
        if msg[1] == id : return True
    return False

# reaction en fonction du message recu
def handle_receive(msg, addr, sock, peer) : 
    try :
        (name, key, root) = peer
        (id, type, length, body, signature) =  decode_message(msg)
        queue_remove(id, name)
        if   type == types['Hello'] :
            helloReply_msg = bytes( encode_helloReply_message(id, NAME)) 
            send_notExpectedReply(helloReply_msg, addr, name, id)
            peer_windows[name]=(DEFAULT_WINDOWS, 0)
        elif type == types['HelloReply'] : 
            peer_windows[name]=(DEFAULT_WINDOWS, 0)
        elif type == types['PublicKey'] : 
            publicKeyReply_msg = bytes(encode_publicKey(id, types['PublicKeyReply']))
            send_notExpectedReply(publicKeyReply_msg, addr, name, id)
        elif type == types['PublicKeyReply'] : 
            err_msg = bytes(encode_error(id, "C'est à "+SERVER_PEER+" que vous devez envoyer un PublicKeyReply"))
            send(sock, err_msg, addr)
        elif type == types['Root'] : 
            rootReply_msg = bytes(encode_root(id, types['RootReply']))
            send_notExpectedReply(rootReply_msg, addr, name, id)
        elif type == types["NatTraversalRequest"] : 
            err_msg = bytes(encode_error(id, "C'est à "+SERVER_PEER+" que vous devez envoyer un NatTraversalRequest"))
            send(sock, err_msg, addr)
        elif type == types["NatTraversal"] : 
            (mapped_ip,port) = body
            isIP4, ip = mapped_to_IP4(mapped_ip), port
            hello_msg = bytes(encode_hello_message(id, NAME))
            if (ip,port) in peers.keys():
                send_notExpectedReply(hello_msg, (ip,port), peers[(ip,port)][0], id+1, interval=3, times=3)
        elif type == types['GetDatum'] : 
            root:Node = state["root"]
            found  = anytree.search.find(root, lambda node: node.name==body)
            if found == None :
                noDatum_msg = bytes(encode_noDatum(id, body))
                send_notExpectedReply(noDatum_msg, addr, name, id)
            else : 
                datum_msg = bytes(encode_datum(id, found.name, found.__dict__['kwargs']["content"]))
                send_notExpectedReply(datum_msg, addr, name, id)
        elif type == types['Datum'] :
            ""
            (d_hash, d_type, d_data) = body
            if d_hash!=hashlib.sha256(msg[39:39+length-32]).digest() : 
                writeLog("[unexpected]bad hash")
            else :
                if d_type == merkle.DIR :
                    pere : Node  = findPere(name, d_hash, merkle.DIR)
                    if pere == None : print("pere not found")
                    pere.__dict__['kwargs']["type"]= merkle.DIR
                    pere.__dict__['kwargs']["has_name"]=True
                    childs_name = [node.name for node in pere.children]
                    for (data_name, data_hash) in d_data :
                        n = data_name.rstrip('\x00')
                        if n not in childs_name : Node(n, parent=pere, kwargs={"type" : 4,"hash" : data_hash, "last_id":id+1, "has_name":True})
                elif d_type == merkle.TREE : 
                    pere : Node  = findPere(name, d_hash, merkle.TREE)
                    if pere != None :
                        if pere.__dict__['kwargs']["type"]==4 :
                            pere.__dict__['kwargs']["type"]= merkle.TREE
                        pere.__dict__['kwargs']["hash_chunk"]= d_data
                        lower = id if "lower" not in pere.__dict__['kwargs'] else pere.__dict__['kwargs']["lower"]
                        upper = 2*MAX_RAND if "upper" not in pere.__dict__['kwargs'] else pere.__dict__['kwargs']["upper"]
                        difference = (upper-lower)
                        ln = len(d_data)+1
                        for i, chunk_hash in enumerate(d_data) : 
                            child_id = lower + difference//(ln-i)

                            datum_msg = bytes(encode_getDatum(child_id, chunk_hash ))
                            send_ExpectedReply(datum_msg, addr, name, child_id, interval=6, times=6)

                            if chunk_hash.hex() not in [node.name for node in pere.children] :
                                Node(chunk_hash.hex(), parent=pere, kwargs={
                                    "type" : 4,
                                    "hash" : chunk_hash,
                                    "last_id" : child_id,
                                    "lower"   : child_id,
                                    "upper"   : lower + difference//(ln-(i+1)),
                                    "has_name":False
                                })
                            pere.__dict__['kwargs']["last_id"] = child_id+1

                elif d_type == merkle.CHUNK : 
                    pere : Node  = findPere(name, d_hash, merkle.CHUNK)
                    if pere != None : 
                        if  pere.__dict__['kwargs']["type"] == 4 : #undefined
                            pere.__dict__['kwargs']["type"]   = merkle.CHUNK
                            pere.__dict__['kwargs']["content"]=d_data
                        else : 
                            writeLog("[unexpected] The unexpected happened !"+ str(pere.__dict__['kwargs']["type"]))
                            Node(id+1, parent=pere, kwargs={
                                    "type" : merkle.CHUNK, "hash" : b"content", "content" : d_data, "has_name":False
                            })
                    else :print("pere not found") 
        elif type == types["NoDatum"] : 
            writeLog("received noDatum from"+ str(addr)+ "\n\t"+ str(body))
        elif type == types["Error"] : 
            writeLog("received error from"+ str(addr)+ "\n\t"+ str(body))
        else : 
            err_msg = bytes(encode_error(id, "Vous m'envoyez un type de message que je ne connais pas encore !"))
            send(sock, err_msg, addr)
            writeLog("Received message of type "+str(type)+":"+str(body))
    except Exception as e: 
         writeLog("[error] "+str(e))



def update(last_time, interval):
    if (time.time() - last_time)>interval :
        while state["processing"]: time.sleep(0.01)
        state["update"]=True
        root:Node=merkle.updateRoot()
        if state["root"].name != root.name : 
            state["root_modified"] = True
        state["root"]=root
        state["update"]=False
        
        update_peers(URL)
        return time.time()
    return last_time


def childs_counter(node:Node) :
    discovered, all = 0,0
    for pre, fill, node in RenderTree(node):
        node_type = node.__dict__['kwargs']["type"]
        if node_type==merkle.CHUNK :
            discovered+=1
            all+=1
        elif node_type==4:
            all+=1 
    return discovered,all

def print_tree(node : Node):
    for pre, fill, n in RenderTree(node):
        node_type = n.__dict__['kwargs']["type"]
        if n.__dict__['kwargs']["has_name"] : 
            if node_type == merkle.TREE:
                (discovered,all)=childs_counter(n)
                if discovered==all : 
                    print("%s%s [%d]" % (pre, n.name, node_type))
                else :
                    print("%s%s [%d]===>[%d/%d]" % (pre, n.name, node_type, discovered, all))
            else :
                print("%s%s [%d]" % (pre, n.name, node_type))


def findNode(str_lst, node : Node):
    lst = str_lst[1:]
    if len(lst) == 0 : 
        return node
    else : 
        for child in node.children : 
            if child.name == lst[0] : return findNode(lst, child)


def input_handle_show(current) : 
    if current[0] == None :
        for name in peers_tree.keys():
            print(name)
    else : 
        node : Node = current[0]
        if node.is_root and (len(node.children)==0): 
            print("to discover root data, type : \nask", current[1], current[1])
        else : 
            print_tree(node)

def input_handle_back(current) :
    if current[0] == None : 
        return (None, "")
    else :
        node : Node = current[0]
        if node.parent == None : 
            return (None, "")
        else : return (node.parent, current[1])

def input_handle_go(current, value : str) :
    input = shlex.split(value)
    if(len(input)!=2) : print("bad input, input = go file")
    elif current[0]==None : 
        if input[1] in peers_tree.keys() : 
            print(peers_tree[input[1]], input[1])
            return (peers_tree[input[1]], input[1])
    else : 
        node : Node = current[0]
        for child in node.children : 
            if input[1] == child.name : 
                print(child)
                return child, current[1]
        print("RETURNING, ", current)
    return current

# ask peer filename
def input_handle_ask(current, value:str) :
    input = shlex.split(value)
    if(len(input)==3):
        name = input[1]
        path = os.path.normpath(input[2]).split(os.path.sep)
        path = path[1:] if path[0] == '' else path
        node : Node = findNode(path, peers_tree[name])
        print("Found : ", node)
        if node == None : print("bad input : peer name or file not found")
        else :
            node.children=[]
            id = random.randint(1, 1000)
            hash = node.__dict__['kwargs']["hash"]
            datum_msg = bytes(encode_getDatum(id, hash ))
            addr = latest_answer_addr_or_random(compatible_addr(name), name, 45)
            send_ExpectedReply(datum_msg,  addr, name, id, interval=6, times=6)
    else : print("bad input : ask peer filename") 


def print_dict(data : dict, isTime : bool) :
    for k in  data.keys() :
        if isTime : print("%s : %d" % (k,time.time()-data[k]))
        else : print( k,":",data[k])

def input_handle_check(value) : 
    input = shlex.split(value)
    if len(input)==2 :
        data = input[1] 
        if   data == "peers": 
            print_dict(peers, False)
        elif data == "peers_addr":
            print_dict(peers_addr, False)
        elif data == "peer_answer_t" : 
            print_dict(peer_answer_t, True)
        elif data == "addr_answer_t" : 
            print_dict(addr_answer_t, True)
        elif data == "time_send" : 
            print_dict(time_send, True)
        elif data == "sign" : 
            print("PUBLIC KEY :",publicKey.to_string())
            print(peers)
        else : print(data, "non existant")
    else : print("bad input") 


def tree_to_lst(tree:Node):
    tree_id, lst = tree.__dict__['kwargs']["last_id"],[]
    for node in tree.children:
        type = node.__dict__['kwargs']["type"]
        id = node.__dict__['kwargs']["last_id"]
        if type==merkle.CHUNK:
            lst.append( (id, node.__dict__['kwargs']["content"]) )
        elif type==merkle.TREE : 
            lst.append(tree_to_lst(node))
    lst.sort(key=lambda x: x[0])
    return lst

def writeTree(lst, file:TextIOWrapper) :
    for item in lst :
        if type(item) is list : 
            writeTree(item, file)
        else : 
            id, data = item
            file.write(data)
    


def import_dir(current:Node, path):
    node_type = current.__dict__['kwargs']["type"]
    if node_type==merkle.CHUNK : 
        if os.path.isfile(path+current.name):
            os.remove(path+current.name)
        with open(path+current.name, "wb") as f : 
            f.write(current.__dict__['kwargs']["content"])
    elif node_type==merkle.TREE : 
        if os.path.isfile(path+current.name):
            os.remove(path+current.name)
        with open(path+current.name, "ab") as f : 
            writeTree(tree_to_lst(current), f)
    elif node_type==merkle.DIR : 
        if not os.path.exists(path+current.name) :
            try : 
                os.makedirs(path+current.name)
            except OSError as exc:
                if exc.errno != errno.EEXIST : raise
        for child in current.children:
            import_dir(child, path+current.name+"/")


def import_tree(name, path): 
    if not os.path.exists(path) :
        try : 
            os.makedirs(path)
        except OSError as exc: 
            if exc.errno != errno.EEXIST : raise
    node = peers_tree[name]
    import_dir(node, path+"/")

def input_handle_out(value) :
    input = shlex.split(value)
    if len(input)==2 :
        data = input[1]
        if data in peers_tree.keys() : 
            import_tree(data, "peers/"+data)
            print("successful")
        else : print(data, "not in", peers_tree.keys())
    else : print("bad input : expected 2 words, ", len(input), "received")

def input_handle_nat(value):
    input = shlex.split(value)
    if len(input)==2 : 
        name = input[1]
        if name in peers_addr.keys() : 
            addr_lst = compatible_addr(name)
            if addr_lst :
                id = random.randint(1, MAX_RAND) 
                hello_msg = bytes(encode_hello_message(id, NAME)) 
                for addr in addr_lst :
                    send_notExpectedReply(hello_msg, addr, name, id, interval=5, times=4)
                time.sleep(6)
                if has_pending_id(id, name) :
                    #envoit un message dans 7 secondes au server si aucun hello n'a été répondu
                    nat_msg = bytes(encode_NatTraversalRequest(id, addr))
                    queue_send(nat_msg, SERVER_PEER, id, 1, 1, False)
            else : print("No address compatible with", name)
    else : print("bad input : expected 2 words, ", len(input), "received")

def waitUpdate() : 
    while state["update"]: 
        print("loading ...")
        time.sleep(5) 

def deadlock_resolver() : 
    if state["processing"]==True and state["update"]==True : 
        state["processing"] = False
        writeLog("[unexpected] dead locked solved")

def notify_root():
    if state["root_modified"] : 
        id = random.randint(1,MAX_RAND)
        root_msg = bytes(encode_root(id, types['RootReply']))
        queue_send(root_msg, SERVER_PEER, id, 3, 3, False)
        writeLog("[notice] root modified")
        state["root_modified"]=False


def updater() : 
    #Cette boucle for initialise time_send
    state["update"]=True
    time_tmp = time.time()
    for name in peers_addr.keys()      : 
        time_send[name]     = time_tmp-100
        peer_answer_t[name] = time_tmp-100
        for addr in peers_addr[name] : 
            addr_answer_t[addr] = time_tmp-100
    timestamp = time.time()-100
    while 1 : 
        time.sleep(1)
        timestamp = update(timestamp, 15)
        deadlock_resolver()

# coeur du protocol
def protocol() :
    while(True) : 
        time.sleep(0.05)
        #met a jour time_send  et envoit en hello a tous les pairs toute les 30 secondes
        if state["update"]==False : 
            state["processing"]=True
            keep_register()
            #gestion des messages recus
            try : 
                notify_root()
                apply_queue()
            except Exception as e: 
                print(e)
                pass
            state["processing"]=False
        for sock in sock_lst : 
            try :
                (msg, addr) = sock.recvfrom(1300)
                if not msg : continue
                addr = ipaddress.ip_address(addr[0]).exploded, addr[1]
                time_tmp = time.time()
                name = peers[addr][0]
                addr_answer_t[addr] = time_tmp
                peer_answer_t[name] = time_tmp
            except Exception as e: 
                continue
            else : 
                if DEBUG : writeLog("<<<"+ str(peers[addr][0])+str(addr)+"\n\t"+ str(decode_message(msg, True)))
                while state["update"]: time.sleep(0.01)
                state["processing"]=True
                handle_receive(msg, addr, sock, peers[addr])
                state["processing"]=False
        


def input_handler():
    current = (None,"")
    while 1 :
        time.sleep(1)
        try : 
            input = select.select([sys.stdin], [], [], 1)[0] 
            if input : 
                print("\n******************************************************\n")
                value = sys.stdin.readline().rstrip()
                while state["update"]: time.sleep(0.01)
                state["processing"]= True 
                print(current)
                if   (value == "q"):
                    print ("Exiting")
                    for sock in sock_lst : sock.close()
                    sys.exit(0)
                elif (value == "show"):
                    input_handle_show(current)
                elif (value == "back") :
                    current = input_handle_back(current)
                elif (value.startswith("go")) : 
                    current = input_handle_go(current, value)
                elif (value.startswith('ask')) : 
                    input_handle_ask(current, value)
                elif (value.startswith("save")) : 
                    input_handle_out(value)
                elif (value.startswith('check')) : 
                    input_handle_check(value)
                elif (value.startswith('nat')) : 
                    input_handle_nat(value)
                print (">: %s" % value)
                print("******************************************************\n")
                state["processing"]=False
        except Exception as e:
            print("[error]", e)
            current = (None,"")


# gestion de la creation de socket
#request_log()
print("fetching local  ipv4 ...")
IPV4 = getlocalIPV4()
if IPV4 is not None : 
    MY_ADDR.append((IPV4, DEFAULT_PORT))
    print("\t",IPV4)
else : print("ipv4 not available.")
print("fetching public ipv6 ...")
IPV6 = getpublicIPV6()
if IPV6 is not None : 
    MY_ADDR.append((IPV6, DEFAULT_PORT))
    print("\t",IPV6)
else : print("ipv6 not available.")
create_socket(MY_ADDR)
if not sock_lst : sys.exit(0) 
print("available addresses :\n\t", MY_ADDR)

update_td   = threading.Thread(target=updater       )
protocol_td = threading.Thread(target=protocol      )
input_td    = threading.Thread(target=input_handler )

print("loading...")
update_peers(URL, True)
waitUpdate()
update_td.start()
protocol_td.start()
input_td.start()


