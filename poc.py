from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
import base64
import os
import hashlib
import random
import string
import binascii
import json
import zlib
import requests
import uuid
import time

def hex_encode(value):
    ALPHABET = "0123456789ABCDEF"
    
    encoded = [
        ALPHABET[(value >> 28) & 0xf],
        ALPHABET[(value >> 24) & 0xf],
        ALPHABET[(value >> 20) & 0xf],
        ALPHABET[(value >> 16) & 0xf],
        ALPHABET[(value >> 12) & 0xf],
        ALPHABET[(value >> 8) & 0xf],
        ALPHABET[(value >> 4) & 0xf],
        ALPHABET[value & 0xf]
    ]
    
    return ''.join(encoded)


def build_crc_table():
    POLYNOMIAL = 0xedb88320
    table = []
    for i in range(256):
        crc = i
        for j in range(8):
            if crc & 1:
                crc = (crc >> 1) ^ POLYNOMIAL
            else:
                crc >>= 1
        table.append(crc)
    return table

def calculate_crc32(data):
    crc_table = build_crc_table()
    crc = 0xffffffff
    for byte in data:
        crc = (crc >> 8) ^ crc_table[(crc ^ byte) & 0xff]
    return crc ^ 0xffffffff

def calculate_checksum(payload):
    utf8_encoded = payload.encode('utf-8')
    crc32_value = calculate_crc32(utf8_encoded)
    hex_encoded = hex_encode(crc32_value)
    return hex_encoded

def satisfy_difficulty(difficulty, hash_string):
    hex_to_bin = {
        '0': '0000', '1': '0001', '2': '0010', '3': '0011',
        '4': '0100', '5': '0101', '6': '0110', '7': '0111',
        '8': '1000', '9': '1001', 'A': '1010', 'B': '1011',
        'C': '1100', 'D': '1101', 'E': '1110', 'F': '1111'
    }

    bin_string = ''.join(hex_to_bin[char.upper()] for char in hash_string[:difficulty // 4])

    bin_int = int(bin_string[:difficulty], 2)

    return bin_int == 0

def sha256_hash(input_string):
    return hashlib.sha256(input_string.encode()).hexdigest()

def encode64(input_bytes):
    return base64.b64encode(input_bytes).decode()

def get_solution_2(payload):
    difficulty = payload['difficulty']
    input_string = payload['input']
    checksum = payload['checksum']
    memory = payload['memory']

    input_checksum_concat = input_string + checksum
    incrementor = 0

    while True:

        input_checksum_0_concat = input_checksum_concat + str(incrementor)
        input_checksum_encoded = input_checksum_0_concat.encode()
        hash_result = hashlib.sha256(input_checksum_encoded).hexdigest()

        if satisfy_difficulty(difficulty, hash_result):
            return str(incrementor)

        incrementor += 1

class KeyProvider:
    def provide(self):
        return {
            'identifier': "KramerAndRio",
            'material': bytes([
                0x4e, 0x2f, 0x88, 0xb3,
                0x12, 0x9d, 0x1b, 0x4e,
                0x79, 0xcf, 0x37, 0x69,
                0xea, 0xb4, 0x5b, 0xcf
            ])
        }

class Encryptor:
    def __init__(self, key_provider):
        self.key_provider = key_provider

    def encrypt(self, plaintext):
        key_data = self.key_provider.provide()
        identifier = key_data['identifier']
        key_material = key_data['material']
        
        hex_key = "93d9f6846b629edb2bdc4466af627d998496cb0c08f9cf043de68d6b25aa9693"
        key = binascii.unhexlify(hex_key)
        
        iv = os.urandom(12)
        
        cipher = Cipher(algorithms.AES(key), modes.GCM(iv), backend=default_backend())

        encryptor = cipher.encryptor()
        
        ciphertext = encryptor.update(plaintext.encode()) + encryptor.finalize()
        tag = encryptor.tag
        
        iv_encoded = base64.b64encode(iv).decode('utf-8')
        tag_hex = tag.hex()
        ciphertext_hex = ciphertext.hex()
        
        result = f"{identifier}::{iv_encoded}::{tag_hex}::{ciphertext_hex}"
        return result
    
    def decrypt(self, iv_encoded, tag_hex, ciphertext_hex):
        key_data = self.key_provider.provide()
        key_material = key_data['material']

        hex_key = "93d9f6846b629edb2bdc4466af627d998496cb0c08f9cf043de68d6b25aa9693"
        key = binascii.unhexlify(hex_key)

        iv = base64.b64decode(iv_encoded)

        tag = bytes.fromhex(tag_hex)
        ciphertext = bytes.fromhex(ciphertext_hex)

        cipher = Cipher(algorithms.AES(key), modes.GCM(iv, tag), backend=default_backend())
        decryptor = cipher.decryptor()

        plaintext = decryptor.update(ciphertext) + decryptor.finalize()

        return plaintext.decode('utf-8')

def main():
    key_provider = KeyProvider()
    encryptor = Encryptor(key_provider)
    metrics = '{"metrics":{"fp2":0,"browser":1,"capabilities":0,"gpu":1,"dnt":0,"math":0,"screen":0,"navigator":0,"auto":0,"stealth":0,"subtle":1,"canvas":39,"formdetector":1,"be":2},"start":' + str(int(time.time())) + ',"gpu":null,"math":{"tan":"-1.4214488238747245","sin":"0.8178819121159085","cos":"-0.5753861119575491"},"flashVersion":null,"plugins":[],"crypto":{"crypto":1,"subtle":0,"encrypt":0,"decrypt":0,"wrapKey":0,"unwrapKey":0,"sign":0,"verify":0,"digest":0,"deriveBits":0,"deriveKey":0,"getRandomValues":true,"randomUUID":true},"canvas":{"hash":-1653648953,"emailHash":null,"histogramBins":[14105,70,77,57,51,65,65,49,47,46,49,39,30,25,40,45,29,55,37,46,48,45,32,26,19,24,39,27,51,34,31,23,21,28,25,31,24,28,32,34,38,15,19,28,22,31,13,22,24,18,39,24,25,35,34,20,19,27,18,17,28,21,19,22,16,20,18,18,20,20,22,25,41,11,26,28,17,23,19,19,20,26,23,9,27,37,28,20,37,12,29,25,38,22,10,25,24,22,39,24,57,26,511,38,26,21,22,30,17,11,24,23,43,25,25,17,24,21,19,59,44,27,32,23,31,26,20,64,18,10,16,28,24,34,33,34,57,17,18,18,16,18,25,23,17,23,21,21,13,26,20,35,21,91,20,29,20,24,11,27,22,23,10,22,23,27,12,32,27,23,25,32,23,17,26,32,17,19,24,30,14,29,27,19,14,29,14,23,25,28,7,25,14,19,20,34,25,38,29,35,35,39,33,20,30,36,22,25,45,29,32,18,28,34,18,29,21,25,23,27,40,30,28,17,37,32,41,43,41,54,18,29,24,34,37,61,51,51,36,35,32,50,55,52,49,65,48,60,67,78,81,70,81,79,205,13505]},"formDetected":true,"numForms":1,"numFormElements":4,"be":{"si":false},"end":' + str(int(time.time()) + 1) + ',"errors":[{"collector":"fp2","message":"screen is not defined"},{"collector":"browser","message":"navigator is not defined"},{"collector":"capabilities","message":"navigator is not defined"},{"collector":"dnt","message":"navigator is not defined"},{"collector":"screen","message":"screen is not defined"},{"collector":"auto","message":"navigator is not defined"}],"version":"2.3.0","id":"' + str(uuid.uuid4()) + '"}'
    checksum = calculate_checksum(metrics)
    print("Checksum calculé :", checksum)
    encrypted_data = encryptor.encrypt(checksum + "#" + metrics)
    print("Début des données chiffrées :", encrypted_data[:50])

    print("Récupération d'un challenge")
    r = requests.get("https://3f38f7f4f368.a20ab67d.eu-south-2.token.awswaf.com/3f38f7f4f368/e1fcfc58118e/inputs?client=browser")
    resp = r.json()

    inputx = resp["challenge"]["input"]
    difficulty = resp["difficulty"]
    memory = 128

    payload = {
        "input": str(inputx),
        "checksum": str(checksum),
        "difficulty": int(difficulty),
        "memory": int(memory)
    }

    print("Challenge récupéré")

    solution = get_solution_2(payload)

    print("Solution au challenge :", str(solution))

    final_payload = {
        "challenge": resp["challenge"],
        "solution": str(solution),
        "checksum": str(checksum),
        "existing_token": "",
        "client": "Browser",
        "domain": "auth.ankama.com",
        "signals": [
            {
                "name": "KramerAndRio",
                "value": {"Present": encrypted_data.replace("KramerAndRio::", "")}
            }
        ],
        "metrics": [{"name":"2","value":0.5608000000000288,"unit":"2"},{"name":"100","value":1,"unit":"2"},{"name":"101","value":0,"unit":"2"},{"name":"102","value":1,"unit":"2"},{"name":"103","value":0,"unit":"2"},{"name":"104","value":0,"unit":"2"},{"name":"105","value":0,"unit":"2"},{"name":"106","value":0,"unit":"2"},{"name":"107","value":0,"unit":"2"},{"name":"108","value":1,"unit":"2"},{"name":"undefined","value":0,"unit":"2"},{"name":"110","value":0,"unit":"2"},{"name":"111","value":40,"unit":"2"},{"name":"112","value":1,"unit":"2"},{"name":"undefined","value":2,"unit":"2"},{"name":"3","value":13.910499999999956,"unit":"2"},{"name":"7","value":0,"unit":"4"},{"name":"1","value":64.99780000000004,"unit":"2"},{"name":"4","value":6.26909999999998,"unit":"2"},{"name":"5","value":0.0013000000000147338,"unit":"2"},{"name":"6","value":71.27339999999998,"unit":"2"},{"name":"8","value":1,"unit":"4"}]
    }

    headers = {
        "accept":"*/*",
        "accept-encoding":"gzip, deflate, br, zstd",
        "accept-language":"fr-FR,fr;q=0.9,en-US;q=0.8,en;q=0.7",
        "content-type":"text/plain;charset=UTF-8",
        "priority":"u=1, i",
        "sec-ch-ua":'"Chromium";v="128", "Not;A=Brand";v="24", "Google Chrome";v="128"',
        "sec-ch-ua-mobile":"?0",
        "sec-ch-ua-platform":'"Windows"',
        "sec-fetch-dest":"empty",
        "sec-fetch-mode":"cors",
        "sec-fetch-site":"cross-site",
        "user-agent":"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.0.0 Safari/537.36"
    }

    print("Envoie de la requête de validation du challenge")

    r2 = requests.post("https://3f38f7f4f368.a20ab67d.eu-south-2.token.awswaf.com/3f38f7f4f368/e1fcfc58118e/verify", json=final_payload, headers=headers)

    print("Token récupéré : ")

    print(r2.json()["token"])

def test_decrypt():
    key_provider = KeyProvider()
    encryptor = Encryptor(key_provider)

    iv_encoded = "" # à remplir
    tag_hex = "" # à remplir
    ciphertext_hex = "" # à remplir
    decrypted = encryptor.decrypt(iv_encoded, tag_hex, ciphertext_hex)
    print(decrypted)

main()
