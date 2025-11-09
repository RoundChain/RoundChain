#!/usr/bin/env python3
"""
傻瓜式钱包控制台  wallet_cli.py
菜单驱动：登录→查余额→转账→连续发币
"""
import json, time, os, sys
import urllib.request, urllib.error
from wallet import load_wallet

SERVER = "http://82.157.37.13:2048"   # 改成你的种子IP

def api(path, data=None):
    try:
        if data:
            body = json.dumps(data).encode()
            req = urllib.request.Request(SERVER + path, data=body, headers={"Content-Type": "application/json"})
        else:
            req = urllib.request.Request(SERVER + path)
        with urllib.request.urlopen(req, timeout=5) as resp:
            return json.load(resp)
    except urllib.error.URLError as e:
        print("[-] 网络错误", e)
        return None

def get_balance(addr):
    st = api(f"/json/balance/{addr}")
    return st["balance"] if st else 0

def send_tx(sender, to, amount, nonce):
    tx = {"sender": sender, "to": to, "amount": amount, "nonce": nonce}
    return api("/json/tx", tx)

def main_menu():
    addr, key = load_wallet()
    print(f"✅ 登录钱包: {addr}")
    while True:
        print("\n---- R2048Wallet ----")
        print("1. 查余额")
        print("2. 转账（自动+1 nonce）")
        print("3. 连续发币 N 笔")
        print("0. 退出")
        choice = input("选操作: ").strip()
        if choice == "1":
            bal = get_balance(addr)
            print(f"💰 当前余额: {bal} RDT")
        elif choice == "2":
            to = input("对方地址: ").strip()
            amt = int(input("转账金额: ").strip())
            # 自动获取下一 nonce
            pool = api("/json/pool")
            used_nonces = {tx["nonce"] for tx in pool["pool"]} if pool else set()
            nonce = 1
            while nonce in used_nonces:
                nonce += 1
            print(f"📤 发送 {amt} RDT 到 {to}  手续费=10  总扣款={amt+10}  nonce={nonce}")
            ok = send_tx(addr, to, amt, nonce)
            if ok and ok.get("status") == "ok":
                print("✅ 发送成功，等待矿工打包")
            else:
                print("❌ 发送失败", ok)
        elif choice == "3":
            to = input("对方地址: ").strip()
            amt = int(input("每笔金额: ").strip())
            count = int(input("发几笔: ").strip())
            pool = api("/json/pool")
            used_nonces = {tx["nonce"] for tx in pool["pool"]} if pool else set()
            nonce = 1
            while nonce in used_nonces:
                nonce += 1
            for i in range(count):
                ok = send_tx(addr, to, amt, nonce + i)
                if ok and ok.get("status") == "ok":
                    print(f"✅ 第{i+1}笔已发送  nonce={nonce+i}")
                else:
                    print(f"❌ 第{i+1}笔失败", ok)
                time.sleep(0.5)
        elif choice == "0":
            print("👋 再见")
            break
        else:
            print("请输入 0-3")

if __name__ == "__main__":
    if not os.path.exists("wallet.key"):
        print("未找到 wallet.key，请先运行 python wallet.py 生成钱包")
        sys.exit(1)
    main_menu()
