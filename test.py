import math
import socket
import ipaddress

import requests

head={"User-Agent": "Mozilla/5.0 (X11; CrOS x86_64 12871.102.0) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/81.0.4044.141 Safari/537.36"}

def ip4to6(ip:str):
    numbers = list(map(int, ip.split('.')))
    ip6 = '2002:{:02x}{:02x}:{:02x}{:02x}::'.format(*numbers)
    return ip6

# -> (bool, str)
def mapped_to_IP4(ip:str): 
    ip6 = ipaddress.ip_address(ip)
    ip6_split = ip6.exploded.split(":")
    for i in range(3, len(ip6_split)-1):
        if ip6_split[i]!='0000' : return False, ip
    num = ip6_split[1]+ip6_split[2]
    return True, ".".join([ str(int(num[i:i+2], 16)) for i in range(0, len(num), 2)])


ip4 = "192.168.1.24"
ip6 = ip4to6(ip4)
m_ip4 = mapped_to_IP4(ip6)

def ip4to6(ip:str):
    numbers = list(map(int, ip.split('.')))
    ip6 = '2002:{:02x}{:02x}:{:02x}{:02x}::'.format(*numbers)
    return ip6

def isIpv4(ip:str):
    try : 
        socket.inet_aton(ip)
        return True
    except : 
        return False

def selectSocket(ip:str) : 
    if isIpv4(ip) : 
        family = socket.AF_INET
    else : family = socket.AF_INET6
    
    my_sock :socket= socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
    return my_sock.family == family  

print(selectSocket("192.168.1.24"))





#https://api.ipify.org/

def getlocalIPV4():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.connect(("8.8.8.8", 80))
    ip = s.getsockname()[0]
    print(ip)
    s.close()

def getpublicIPV6() : 
    try :
        server_r = requests.get(url="https://api.ipify.org/", headers=head, timeout=5)
        return server_r.text
    except : 
        return None



#getlocalIPV4()
#getpublicIPV6()

addr = socket.inet_pton(socket.AF_INET6, '2a01:04f9:c010:cf6d:0000:0000:0000:0001')

print(addr)

m_addr = mapped_to_IP4('2002:51c2:1b9b::')
print(m_addr)

print(isIpv4('2002:51c2:1b9b::'))

import shlex

msg = "nat ok \"lol\""
print(shlex.split(msg))



#sign = privateKey.sign(b"lol")
#sign2 = privateKey.sign(b"lol")
#ok = publicKey.verify(sign, b"lol")
#pk = ecdsa.VerifyingKey.from_string(publicKey.to_string(), curve=ecdsa.SECP256k1, hashfunc=hashlib.sha256)
#ok2 = pk.verify(sign, b"lol")

#h = hashlib.sha256(NAME.encode()).digest()
#print(  h  )

#keymsg = bytes(encode_publicKey(42, 1))
#pkey = keymsg[7:64+7]

#signKey = ecdsa.VerifyingKey.from_string(pkey, curve=ecdsa.SECP256k1, hashfunc=hashlib.sha256)

#hello = bytes(encode_hello_message(42, NAME))
#clair = hello[0:len(hello)-64]
#signed = hello[len(hello)-64:len(hello)]
#print(clair)
#print(signed)

#test = signKey.verify(signed, clair)

#print(test)

