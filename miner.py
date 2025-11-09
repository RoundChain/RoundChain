#!/usr/bin/env python3
import json, time, hashlib, urllib.request, urllib.error, threading
from dataclasses import dataclass, asdict
from wallet import load_wallet

SERVER = "http://82.157.37.13:2048"
BLOCK_INTERVAL = 60

MY_ADDR, MY_KEY = load_wallet()
MY_ID = MY_ADDR

@dataclass
class Block:
    height: int; prev_hash: str; miner: str; txs: list
    reward: int = 1640; fee_total: int = 0; hash: str = ""
    def __post_init__(self):
        self.fee_total = len(self.txs) * 10
        self.hash = hashlib.sha256(f"{self.height}{self.prev_hash}{self.miner}{self.fee_total}".encode()).hexdigest()

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

def join():
    return api("/json/join", {"node_id": MY_ID})

def get_state():
    return api("/json/queue")

def submit_block(blk: Block):
    return api("/json/block", asdict(blk))

# 心跳线程
def heartbeat():
    while True:
        try:
            api("/json/ping", {"addr": MY_ID})
        except:
            pass
        time.sleep(30)

def main():
    join()
    threading.Thread(target=heartbeat, daemon=True).start()
    while True:
        st = get_state()
        if not st:
            time.sleep(5)
            continue
        queue, height, prev_hash = st["queue"], st["height"], st["prev_hash"]
        print(f"[*] 队列 {queue}")
        if queue and queue[0] == MY_ID:
            blk = Block(height + 1, prev_hash, MY_ID, [])
            print(f"[⚒] 出块 #{blk.height}")
            ok = submit_block(blk)
            if ok and ok.get("status") == "ok":
                print(f"[✓] 提交成功")
        time.sleep(BLOCK_INTERVAL)

if __name__ == "__main__":
    main()
