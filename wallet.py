#!/usr/bin/env python3
import json, os
from nacl.signing import SigningKey
import nacl.encoding

def new_wallet(file_name="wallet.key"):
    key = SigningKey.generate()
    addr = key.verify_key.encode(encoder=nacl.encoding.HexEncoder).decode()[:32]
    with open(file_name, "w") as f:
        json.dump({"private_key": key.encode(encoder=nacl.encoding.HexEncoder).decode(),
                   "address": addr}, f)
    print(f"地址: {addr}")
    print(f"私钥已保存: {file_name}")
    return addr, key

def load_wallet(file_name="wallet.key"):
    with open(file_name) as f:
        j = json.load(f)
    key = SigningKey(j["private_key"], encoder=nacl.encoding.HexEncoder)
    return j["address"], key

if __name__ == "__main__":
    new_wallet()
