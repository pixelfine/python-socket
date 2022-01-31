import certifi
import requests
import os

URL= 'https://jch.irif.fr:8082' 
CERTI_PATH= 'jch-irif-fr.pem'

try:
    requests.get(URL + '/peers/')
except Exception:
    cert = open(CERTI_PATH, 'r')
    cacert = open(certifi.where(), 'a')
    cacert.seek(0, os.SEEK_END)
    cacert.write('\n')
    cacert.write(cert.read())
    cacert.close()
    cert.close()
    print('Certificate was added!')