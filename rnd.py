#!/usr/bin/env python3
"""RND节点程序：多节点集群（9755/9756端口) - 无算力+动态白名单+防篡改版"""
import json
import time
import hashlib
import http.server
import socketserver
import sqlite3
import threading
import requests
from dataclasses import dataclass, asdict
from nacl.signing import SigningKey, VerifyKey
import nacl.encoding
from typing import List, Dict, Set, Optional, Tuple
import random
from cryptography.fernet import Fernet
import os
import socket
import atexit

# ---------- 节点核心配置 ----------
PORT = 9756  # 主服务端口
DB_FILE = "node.db"  # 全量存储数据库
REWARD = 1280
TOTAL_SUPPLY_LIMIT = 12800000000
FEE = 1
TIMEOUT = 180
SYNC_INTERVAL = 10
P2P_DISCOVERY_PORT = 9755 # P2P端口
TX_SYNC_INTERVAL = 10
WALLET_DIR = "./rnd_wallet"  # 独立钱包目录
ENCRYPT_KEY_FILE = f"{WALLET_DIR}/encrypt_key.key"
CURRENT_NODE_PUBLIC_IP = "62.234.183.74"  # 节点公网IP（可修改为实际IP）
P2P_SEEDS = ["82.157.37.13:9753"]  # 对等节点，可填写多个
MAX_TX_POOL_SIZE = 1000  # 交易池最大容量
REQUEST_LIMIT_PER_MINUTE = 100  # 单IP每分钟最大请求数

# 36位地址配置（RNDC前缀+32位哈希）
ADDRESS_PREFIX = "RNDC"
ADDRESS_LENGTH = 36  # 前缀4位 + 哈希32位
VALID_CHARS = "23456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"  # 过滤模糊字符

# 白名单配置（核心新增）
WHITELIST_CONSENSUS_RATIO = 0.6  # 新增节点需60%以上已认证节点认可
WHITELIST_VALIDITY_PERIOD = 86400  # 白名单有效期24小时
IP_BIND_LOCK = threading.Lock()

# ---------- 全局变量 ----------
NODE_ADDR = ""
NODE_KEY = None
ENCRYPTOR = None
NODE_IP = ""
P2P_PEERS = {}
GLOBAL_QUEUE = []
TX_POOL = []
BALANCE_CACHE = {}  # {addr_maxheight: balance}
IP_ADDR_MAP = {}
ADDR_IP_MAP = {}
IP_REQUEST_COUNT = {}  # {ip: (count, last_reset_time)} 限流用
QUEUE_LOCK = threading.Lock()
TX_POOL_LOCK = threading.Lock()
IS_SYNCING = False
IS_TX_SYNCING = False
IS_FULLY_SYNCED = False
P2P_HEIGHT_CACHE = {}  # {peer_main_addr: (height, timestamp)}
GLOBAL_REQUEST_SEMAPHORE = threading.Semaphore(20)  # 全局并发限制

# 白名单相关全局变量（核心新增）
AUTHENTICATED_NODES = set()  # 已认证的合法节点（白名单）
NODE_WHITELIST_REQUESTS = {}  # 白名单加入请求：{节点地址: {认可节点: 时间}}

# ---------- 核心数据结构 ----------
@dataclass
class Block:
    height: int
    prev_hash: str
    miner: str
    txs: List[Dict]
    reward: int

# ---------- 工具函数 ----------
def log_print(msg: str):
    """带时间戳的日志打印函数"""
    timestamp = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())
    print(f"[{timestamp}] {msg}")

def get_local_ip() -> str:
    """获取本地IP"""
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(('8.8.8.8', 80))
        ip = s.getsockname()[0]
    finally:
        s.close()
    return ip

def init_wallet_dir():
    """初始化钱包存储目录"""
    os.makedirs(WALLET_DIR, exist_ok=True)
    # 生成加密密钥（首次运行）
    if not os.path.exists(ENCRYPT_KEY_FILE):
        encrypt_key = Fernet.generate_key()
        with open(ENCRYPT_KEY_FILE, "wb") as f:
            f.write(encrypt_key)
    # 加载加密器
    with open(ENCRYPT_KEY_FILE, "rb") as f:
        encrypt_key = f.read()
    return Fernet(encrypt_key)

def generate_36bit_address(public_key: str) -> str:
    """生成36位RNDC地址（过滤模糊字符）"""
    hash_hex = hashlib.sha256(public_key.encode()).hexdigest()[:64]
    filtered_chars = [c for c in hash_hex if c in VALID_CHARS][:32]
    address = f"{ADDRESS_PREFIX}{''.join(filtered_chars)}"
    if len(address) != ADDRESS_LENGTH:
        raise ValueError(f"地址生成失败：长度为{len(address)}位（预期36位）")
    return address

def load_wallet(encryptor: Fernet) -> Optional[Tuple[SigningKey, str, str]]:
    """加载已存在的钱包"""
    wallet_files = [f for f in os.listdir(WALLET_DIR) if f.startswith("rndc_wallet_") and f.endswith(".json")]
    if not wallet_files:
        return None
    wallet_path = os.path.join(WALLET_DIR, wallet_files[0])
    with open(wallet_path, "rb") as f:
        encrypted_data = f.read()
    data = json.loads(encryptor.decrypt(encrypted_data).decode())
    private_key = SigningKey(data["private_key"], encoder=nacl.encoding.HexEncoder)
    public_key = data["public_key"]
    address = data["address"]
    return private_key, public_key, address

def create_new_wallet(encryptor: Fernet) -> Tuple[SigningKey, str, str]:
    """创建新钱包（36位RNDC地址）"""
    private_key = SigningKey.generate()
    public_key = private_key.verify_key.encode(encoder=nacl.encoding.HexEncoder).decode()
    address = generate_36bit_address(public_key)
    # 加密存储
    wallet_data = {
        "private_key": private_key.encode(encoder=nacl.encoding.HexEncoder).decode(),
        "public_key": public_key,
        "address": address,
        "create_time": time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())
    }
    wallet_path = os.path.join(WALLET_DIR, f"rndc_wallet_{address}.json")
    with open(wallet_path, "wb") as f:
        f.write(encryptor.encrypt(json.dumps(wallet_data).encode()))
    print(f"✅ 新钱包创建成功！")
    print(f"  address: {address}")
    print(f"🔑 私钥已加密存储（路径：{wallet_path}）")
    return private_key, public_key, address

def init_wallet() -> Tuple[SigningKey, str, Fernet]:
    """节点钱包初始化入口（加载已有/创建新钱包）"""
    encryptor = init_wallet_dir()
    wallet = load_wallet(encryptor)
    if wallet:
        private_key, public_key, address = wallet
        log_print(f"[钱包加载] 36位地址：{address}")
        return private_key, address, encryptor
    # 没有则创建新钱包
    private_key, public_key, address = create_new_wallet(encryptor)
    log_print(f"[钱包生成] 36位地址：{address}")
    return private_key, address, encryptor

def bind_ip_address(ip: str, addr: str):
    """绑定IP与地址"""
    with IP_BIND_LOCK:
        IP_ADDR_MAP[ip] = addr
        ADDR_IP_MAP[addr] = ip
        conn = sqlite3.connect(DB_FILE)
        cur = conn.cursor()
        cur.execute("CREATE TABLE IF NOT EXISTS ip_addr_map(ip TEXT PRIMARY KEY, addr TEXT)")
        cur.execute("INSERT OR REPLACE INTO ip_addr_map(ip, addr) VALUES (?, ?)", (ip, addr))
        conn.commit()
        conn.close()

def load_ip_addr_map():
    """加载IP与地址映射"""
    try:
        conn = sqlite3.connect(DB_FILE)
        cur = conn.cursor()
        cur.execute("CREATE TABLE IF NOT EXISTS ip_addr_map(ip TEXT PRIMARY KEY, addr TEXT)")
        rows = cur.execute("SELECT ip, addr FROM ip_addr_map").fetchall()
        conn.close()
        with IP_BIND_LOCK:
            for ip, addr in rows:
                IP_ADDR_MAP[ip] = addr
                ADDR_IP_MAP[addr] = ip
    except Exception as e:
        log_print(f"[错误] IP映射加载失败：{e}")

def load_p2p_peers():
    """加载P2P节点列表"""
    try:
        conn = sqlite3.connect(DB_FILE)
        cur = conn.cursor()
        cur.execute("CREATE TABLE IF NOT EXISTS p2p_peers(peer_addr TEXT PRIMARY KEY, add_time REAL)")
        rows = cur.execute("SELECT peer_addr, add_time FROM p2p_peers").fetchall()
        conn.close()
        with IP_BIND_LOCK:
            for addr, add_time in rows:
                P2P_PEERS[addr] = add_time
    except Exception as e:
        log_print(f"[错误] P2P节点加载失败：{e}")

# ---------- 安全相关函数 ----------
def is_valid_address(addr: str) -> bool:
    """验证地址是否为36位RNDC格式"""
    return len(addr) == ADDRESS_LENGTH and addr.startswith(ADDRESS_PREFIX)

def verify_tx_signature(tx: Dict) -> bool:
    """验证交易签名有效性"""
    required_fields = ["sender", "signature", "public_key", "amount", "recipient", "nonce"]
    if not all(field in tx for field in required_fields):
        log_print(f"[交易验证失败] 字段缺失")
        return False
    # 验证地址格式
    if not is_valid_address(tx["sender"]) or not is_valid_address(tx["recipient"]):
        log_print(f"[交易验证失败] 地址格式无效")
        return False
    try:
        public_key = VerifyKey(tx["public_key"], encoder=nacl.encoding.HexEncoder)
        tx_data = {k: v for k, v in tx.items() if k != "signature"}
        tx_json = json.dumps(tx_data, sort_keys=True).encode()
        public_key.verify(tx_json, bytes.fromhex(tx["signature"]))
        return True
    except Exception as e:
        log_print(f"[交易验证失败] {tx['sender'][:8]}：{e}")
        return False

def is_peer_alive(peer_main_addr: str) -> bool:
    """检测P2P节点是否存活"""
    try:
        resp = requests.get(f"http://{peer_main_addr}/json/chain_height", timeout=5)
        return resp.status_code == 200
    except Exception:
        return False

# ---------- 区块相关函数 ----------
def init_full_chain_db():
    """初始化全量区块数据库（含哈希字段）"""
    conn = sqlite3.connect(DB_FILE)
    cur = conn.cursor()
    cur.execute("""
        CREATE TABLE IF NOT EXISTS blocks (
            height INTEGER PRIMARY KEY,
            prev_hash TEXT NOT NULL,
            miner TEXT NOT NULL,
            txs TEXT NOT NULL,
            reward INTEGER NOT NULL,
            create_time REAL NOT NULL,
            block_hash TEXT NOT NULL UNIQUE  -- 存储区块哈希，用于防篡改
        )
    """)
    conn.commit()
    conn.close()

def get_total_supply(up_to_height: int = None) -> int:
    """获取指定高度前的总发行量"""
    if up_to_height is None:
        up_to_height = get_chain_height()
    try:
        conn = sqlite3.connect(DB_FILE)
        cur = conn.cursor()
        cur.execute("SELECT SUM(reward) FROM blocks WHERE height <= ?", (up_to_height,))
        row = cur.fetchone()
        conn.close()
        return row[0] if row[0] is not None else 0
    except Exception as e:
        log_print(f"[错误] 计算总发行量失败：{e}")
        return 0

def verify_block_chain(height: int) -> bool:
    """验证区块链完整性"""
    if height == 0:
        return True
    current_block = get_block_from_full_chain(height)
    prev_block = get_block_from_full_chain(height - 1)
    if not current_block or not prev_block:
        return False
    # 验证矿工地址格式
    if not is_valid_address(current_block.miner):
        log_print(f"[区块验证失败] 高度{height}矿工地址格式无效")
        return False
    prev_block_hash = hashlib.sha256(json.dumps(asdict(prev_block)).encode()).hexdigest()
    return current_block.prev_hash == prev_block_hash

def get_block_from_full_chain(height: int) -> Optional[Block]:
    """从全量数据库查询区块"""
    try:
        conn = sqlite3.connect(DB_FILE)
        cur = conn.cursor()
        cur.execute("SELECT prev_hash, miner, txs, reward FROM blocks WHERE height=?", (height,))
        row = cur.fetchone()
        conn.close()
        if row:
            return Block(
                height=height,
                prev_hash=row[0],
                miner=row[1],
                txs=json.loads(row[2]),
                reward=row[3]
            )
    except Exception as e:
        log_print(f"[错误] 查询区块{height}异常：{e}")
    return None

def save_block_to_full_chain(block: Block):
    """保存区块（强化校验：白名单+奖励+交易合法性）"""
    # 1. 校验矿工是否在白名单
    if block.miner not in AUTHENTICATED_NODES:
        log_print(f"[保存失败] 区块{block.height}矿工{block.miner[:8]}... 不在白名单")
        return
    # 2. 校验奖励合法性
    current_supply = get_total_supply()
    valid_reward = REWARD if (current_supply + REWARD) <= TOTAL_SUPPLY_LIMIT else 0
    if block.reward != valid_reward:
        log_print(f"[保存失败] 区块{block.height}奖励异常（预期{valid_reward}，实际{block.reward}）")
        return
    # 3. 校验区块高度连续性
    current_max_height = get_chain_height()
    if block.height != current_max_height + 1:
        log_print(f"[保存失败] 区块{block.height}高度不连续（当前最高{current_max_height}）")
        return
    # 4. 校验矿工地址格式
    if not is_valid_address(block.miner):
        log_print(f"[保存失败] 区块{block.height}矿工地址格式无效")
        return
    # 5. 校验交易合法性
    for tx in block.txs:
        if not verify_tx_signature(tx):
            log_print(f"[保存失败] 区块{block.height}包含无效交易：{tx['sender'][:8]}...")
            return
        sender_bal = get_balance_from_cache(tx["sender"], current_max_height)
        if sender_bal < (tx["amount"] + FEE):
            log_print(f"[保存失败] 区块{block.height}交易余额不足")
            return
    # 6. 计算并存储区块哈希（防篡改）
    block_dict = asdict(block)
    block_hash = hashlib.sha256(json.dumps(block_dict, sort_keys=True).encode()).hexdigest()
    # 7. 保存到数据库
    conn = sqlite3.connect(DB_FILE)
    cur = conn.cursor()
    cur.execute("""
        INSERT OR REPLACE INTO blocks 
        (height, prev_hash, miner, txs, reward, create_time, block_hash)
        VALUES (?, ?, ?, ?, ?, ?, ?)
    """, (
        block.height,
        block.prev_hash,
        block.miner,
        json.dumps(block.txs),
        block.reward,
        time.time(),
        block_hash
    ))
    conn.commit()
    conn.close()
    log_print(f"[全量存储] 区块{block.height}已保存（矿工：{block.miner[:8]}... 哈希：{block_hash[:8]}...）")
    # 8. 清理相关地址余额缓存
    with IP_BIND_LOCK:
        cache_keys = list(BALANCE_CACHE.keys())
        related_addrs = {block.miner}
        for tx in block.txs:
            related_addrs.add(tx["sender"])
            related_addrs.add(tx["recipient"])
        for key in cache_keys:
            addr = key.split("_")[0]
            if addr in related_addrs:
                del BALANCE_CACHE[key]

def get_chain_height() -> int:
    """获取全量链的最高高度"""
    try:
        conn = sqlite3.connect(DB_FILE)
        cur = conn.cursor()
        cur.execute("SELECT MAX(height) FROM blocks")
        row = cur.fetchone()
        conn.close()
        return row[0] if row[0] is not None else 0
    except Exception as e:
        log_print(f"[错误] 查询链高异常：{e}")
        return 0

def verify_local_chain_integrity():
    """启动时校验本地数据完整性（防篡改）"""
    log_print("[校验] 开始本地链完整性校验...")
    max_height = get_chain_height()
    invalid_blocks = []
    for height in range(1, max_height + 1):
        try:
            conn = sqlite3.connect(DB_FILE)
            cur = conn.cursor()
            cur.execute("SELECT prev_hash, miner, txs, reward, block_hash FROM blocks WHERE height=?", (height,))
            row = cur.fetchone()
            conn.close()
            if not row:
                invalid_blocks.append(f"高度{height}：区块缺失")
                continue
            prev_hash, miner, txs, reward, stored_hash = row
            # 校验奖励合法性
            current_supply = get_total_supply(height - 1)
            valid_reward = REWARD if (current_supply + REWARD) <= TOTAL_SUPPLY_LIMIT else 0
            if reward != valid_reward:
                invalid_blocks.append(f"高度{height}：奖励异常（实际{reward}，预期{valid_reward}）")
            # 校验区块哈希
            block = Block(
                height=height,
                prev_hash=prev_hash,
                miner=miner,
                txs=json.loads(txs),
                reward=reward
            )
            calc_hash = hashlib.sha256(json.dumps(asdict(block), sort_keys=True).encode()).hexdigest()
            if calc_hash != stored_hash:
                invalid_blocks.append(f"高度{height}：哈希篡改（存储{stored_hash[:8]}... 计算{calc_hash[:8]}...）")
        except Exception as e:
            invalid_blocks.append(f"高度{height}：校验失败：{str(e)}")
    # 输出结果
    if invalid_blocks:
        log_print(f"[错误] 发现{len(invalid_blocks)}个篡改/异常区块，建议重置数据！")
        for err in invalid_blocks[:5]:
            log_print(f"  - {err}")
    else:
        log_print(f"[校验完成] 本地链（高度{max_height}）无篡改，数据完整")

# ---------- 白名单管理函数（核心新增） ----------
def request_whitelist_join(node_addr: str):
    """节点申请加入白名单"""
    if node_addr in AUTHENTICATED_NODES:
        log_print(f"[白名单] 节点{node_addr[:8]}... 已在白名单中")
        return True
    with IP_BIND_LOCK:
        if node_addr not in NODE_WHITELIST_REQUESTS:
            NODE_WHITELIST_REQUESTS[node_addr] = {}
        NODE_WHITELIST_REQUESTS[node_addr][NODE_ADDR] = time.time()
    # 向所有已认证节点广播加入请求
    for peer_addr in AUTHENTICATED_NODES:
        if peer_addr == NODE_ADDR:
            continue
        try:
            requests.post(
                f"http://{peer_addr}/json/whitelist/request",
                json={"node_addr": node_addr, "requester": NODE_ADDR},
                timeout=5
            )
        except Exception as e:
            log_print(f"[白名单] 向节点{peer_addr[:8]}... 发送请求失败：{e}")
    log_print(f"[白名单] 节点{node_addr[:8]}... 已发起加入请求，等待共识")
    return False

def approve_whitelist_request(request_node: str, approver_node: str):
    """认可节点加入白名单（仅已认证节点可投票）"""
    if approver_node not in AUTHENTICATED_NODES:
        log_print(f"[白名单] 节点{approver_node[:8]}... 未认证，无权认可")
        return
    with IP_BIND_LOCK:
        if request_node not in NODE_WHITELIST_REQUESTS:
            NODE_WHITELIST_REQUESTS[request_node] = {}
        NODE_WHITELIST_REQUESTS[request_node][approver_node] = time.time()
    # 检查是否达到共识比例
    approve_count = len(NODE_WHITELIST_REQUESTS[request_node])
    total_authenticated = len(AUTHENTICATED_NODES)
    if total_authenticated == 0:
        # 无已认证节点时，首次加入直接通过
        AUTHENTICATED_NODES.add(request_node)
        log_print(f"[白名单] 无已认证节点，节点{request_node[:8]}... 直接加入")
        return
    if approve_count / total_authenticated >= WHITELIST_CONSENSUS_RATIO:
        # 达到共识比例，加入白名单
        AUTHENTICATED_NODES.add(request_node)
        if request_node in NODE_WHITELIST_REQUESTS:
            del NODE_WHITELIST_REQUESTS[request_node]
        broadcast_whitelist_update()
        log_print(f"[白名单] 节点{request_node[:8]}... 获得{approve_count}/{total_authenticated}认可，加入白名单")

def broadcast_whitelist_update():
    """广播白名单更新给所有P2P节点"""
    for peer_addr in P2P_PEERS:
        try:
            requests.post(
                f"http://{peer_addr}/json/whitelist/update",
                json={"authenticated_nodes": list(AUTHENTICATED_NODES)},
                timeout=5
            )
        except Exception as e:
            log_print(f"[白名单] 向节点{peer_addr[:8]}... 广播更新失败：{e}")

def sync_whitelist(remote_authenticated_nodes: list):
    """同步其他节点的白名单"""
    with IP_BIND_LOCK:
        local_count = len(AUTHENTICATED_NODES)
        remote_count = len(remote_authenticated_nodes)
        if remote_count > local_count and all(is_valid_address(node) for node in remote_authenticated_nodes):
            AUTHENTICATED_NODES.clear()
            AUTHENTICATED_NODES.update(remote_authenticated_nodes)
            log_print(f"[白名单] 同步远程白名单，当前合法节点数：{len(AUTHENTICATED_NODES)}")

def clean_expired_whitelist():
    """清理过期白名单节点（每小时执行）"""
    while True:
        time.sleep(3600)
        with IP_BIND_LOCK:
            current_time = time.time()
            expired_nodes = []
            for node_addr in AUTHENTICATED_NODES:
                if node_addr not in P2P_PEERS or (current_time - P2P_PEERS[node_addr]) > WHITELIST_VALIDITY_PERIOD:
                    expired_nodes.append(node_addr)
            for node_addr in expired_nodes:
                AUTHENTICATED_NODES.remove(node_addr)
                log_print(f"[白名单] 节点{node_addr[:8]}... 过期/离线，移出白名单")
            if expired_nodes:
                broadcast_whitelist_update()

# ---------- P2P同步相关函数 ----------
def save_p2p_peer(peer_main_addr: str):
    """保存P2P节点"""
    with IP_BIND_LOCK:
        if peer_main_addr not in P2P_PEERS:
            P2P_PEERS[peer_main_addr] = time.time()
            conn = sqlite3.connect(DB_FILE)
            cur = conn.cursor()
            cur.execute("CREATE TABLE IF NOT EXISTS p2p_peers(peer_addr TEXT PRIMARY KEY, add_time REAL)")
            cur.execute("INSERT OR REPLACE INTO p2p_peers(peer_addr, add_time) VALUES (?, ?)", (peer_main_addr, time.time()))
            conn.commit()
            conn.close()

def p2p_discover_loop():
    """P2P发现线程（含节点心跳检测）"""
    while True:
        time.sleep(5)
        initial_seeds = P2P_SEEDS.copy()
        all_candidates = initial_seeds + list(P2P_PEERS.keys())
        random.shuffle(all_candidates)
        invalid_ips = {"127.0.0.1", "localhost", NODE_IP}
        local_main_addr = f"{CURRENT_NODE_PUBLIC_IP}:{PORT}"
        for candidate in all_candidates[:3]:
            if ":" not in candidate:
                continue
            peer_ip = candidate.rsplit(":", 1)[0]
            if peer_ip in invalid_ips:
                continue
            try:
                resp = requests.get(f"http://{candidate}/p2p/peers", timeout=10)
                if resp.status_code == 200:
                    data = resp.json()
                    if data["local_main_addr"] not in P2P_PEERS and data["local_main_addr"] != local_main_addr:
                        peer_main_ip = data["local_main_addr"].rsplit(":", 1)[0]
                        if peer_main_ip not in invalid_ips:
                            save_p2p_peer(data["local_main_addr"])
                    for peer_main_addr in data["peers"]:
                        if peer_main_addr not in P2P_PEERS and peer_main_addr != local_main_addr:
                            peer_main_ip = peer_main_addr.rsplit(":", 1)[0]
                            if peer_main_ip not in invalid_ips:
                                save_p2p_peer(peer_main_addr)
            except Exception as e:
                continue
        # 清理无效节点
        now = time.time()
        invalid_peers = []
        for addr in P2P_PEERS:
            if now - P2P_PEERS[addr] > 3600 or not is_peer_alive(addr):
                invalid_peers.append(addr)
        for addr in invalid_peers:
            del P2P_PEERS[addr]
            conn = sqlite3.connect(DB_FILE)
            cur = conn.cursor()
            cur.execute("DELETE FROM p2p_peers WHERE peer_addr=?", (addr,))
            conn.commit()
            conn.close()
            log_print(f"[P2P清理] 移除无效节点：{addr}")

def sync_missing_blocks_from_peers():
    """区块同步（含白名单+算力校验）"""
    global IS_SYNCING, IS_FULLY_SYNCED
    if IS_SYNCING:
        return
    IS_SYNCING = True
    try:
        local_max_height = get_chain_height()
        p2p_max_height = 0
        valid_p2p_nodes = []
        invalid_ips = {"127.0.0.1", "localhost", NODE_IP}
        valid_peers = [peer for peer in P2P_PEERS if not any(ip in peer for ip in invalid_ips)]
        # 获取有效节点和目标链高
        for peer_main_addr in valid_peers:
            try:
                resp = requests.get(f"http://{peer_main_addr}/json/chain_height", timeout=10)
                if resp.status_code == 200:
                    peer_height = resp.json()["height"]
                    if peer_height > p2p_max_height:
                        p2p_max_height = peer_height
                    valid_p2p_nodes.append(peer_main_addr)
            except:
                continue
        if not valid_p2p_nodes:
            IS_FULLY_SYNCED = True
            log_print(f"♻️[同步完成] 无有效P2P节点，单节点模式")
            return
        if p2p_max_height > local_max_height:
            log_print(f"♻️[同步] P2P最高{p2p_max_height} > 本地{local_max_height}，开始同步")
            batch_size = 10
            for batch_start in range(local_max_height + 1, p2p_max_height + 1, batch_size):
                batch_end = min(batch_start + batch_size - 1, p2p_max_height)
                log_print(f"♻️[批次同步] 同步区块 {batch_start}-{batch_end}")
                for height in range(batch_start, batch_end + 1):
                    block = None
                    block_hash_map = {}
                    retry_count = 0
                    # 收集多节点区块，验证合法性
                    while retry_count < 3 and len(block_hash_map) < 2:
                        for peer_main_addr in valid_p2p_nodes:
                            try:
                                time.sleep(0.5)
                                resp = requests.get(f"http://{peer_main_addr}/json/block/{height}", timeout=20)
                                if resp.status_code == 429:
                                    log_print(f"♻️[限流触发] 节点{peer_main_addr}请求频繁，暂停30秒")
                                    time.sleep(30)
                                    continue
                                if resp.status_code == 200:
                                    peer_block = resp.json()["block"]
                                    # 校验区块基本合法性
                                    if not is_valid_address(peer_block["miner"]):
                                        continue
                                    # 计算区块哈希
                                    calc_dict = {k: v for k, v in peer_block.items() if k != "prev_hash"}
                                    block_hash = hashlib.sha256(json.dumps(calc_dict, sort_keys=True).encode()).hexdigest()
                                    # 统计哈希共识
                                    if block_hash in block_hash_map:
                                        block_hash_map[block_hash] += 1
                                    else:
                                        block_hash_map[block_hash] = 1
                            except:
                                continue
                        retry_count += 1
                    # 获取共识区块
                    if block_hash_map:
                        consensus_hash = max(block_hash_map.items(), key=lambda x: x[1])[0]
                        for peer_main_addr in valid_p2p_nodes:
                            try:
                                time.sleep(0.5)
                                resp = requests.get(f"http://{peer_main_addr}/json/block/{height}", timeout=20)
                                if resp.status_code == 200:
                                    peer_block = resp.json()["block"]
                                    calc_dict = {k: v for k, v in peer_block.items() if k != "prev_hash"}
                                    if hashlib.sha256(json.dumps(calc_dict, sort_keys=True).encode()).hexdigest() == consensus_hash:
                                        block = Block(**peer_block)
                                        break
                            except:
                                continue
                    # 保存区块
                    if block:
                        save_block_to_full_chain(block)
                        log_print(f"♻️ [同步成功] 高度{height}（共识哈希：{consensus_hash[:8]}...）")
                    else:
                        log_print(f"♻️[同步失败] 高度{height}（未达成共识）")
                time.sleep(10)
            local_max_height = get_chain_height()
        IS_FULLY_SYNCED = local_max_height >= p2p_max_height
        status = "完成" if IS_FULLY_SYNCED else "中"
        log_print(f"♻️[同步{status}] 本地{local_max_height} | 集群{p2p_max_height}")
    finally:
        IS_SYNCING = False

def sync_loop():
    """同步循环线程"""
    while True:
        sync_missing_blocks_from_peers()
        time.sleep(SYNC_INTERVAL)

# ---------- 挖矿相关函数 ----------
def get_balance_from_cache(addr: str, max_height: int) -> int:
    """按地址+最大高度缓存余额"""
    if not is_valid_address(addr):
        log_print(f"[余额计算失败] 地址格式无效：{addr}")
        return 0
    cache_key = f"{addr}_{max_height}"
    if cache_key in BALANCE_CACHE:
        return BALANCE_CACHE[cache_key]
    balance = 0
    try:
        # 遍历全量区块计算余额
        for height in range(1, max_height + 1):
            block = get_block_from_full_chain(height)
            if not block:
                continue
            # 累加矿工奖励
            if block.miner == addr:
                balance += block.reward
            # 处理交易
            for tx in block.txs:
                if tx.get("sender") == addr:
                    balance = max(0, balance - (tx["amount"] + FEE))
                if tx.get("recipient") == addr:
                    balance += tx["amount"]
    except Exception as e:
        log_print(f"[错误] 计算地址{addr[:8]}...余额失败：{e}")
        balance = 0
    # 缓存结果
    BALANCE_CACHE[cache_key] = max(balance, 0)
    return BALANCE_CACHE[cache_key]

def miner_loop():
    """挖矿循环线程（仅白名单节点可挖矿）"""
    global IS_FULLY_SYNCED, TX_POOL
    # 启动时自动申请加入白名单
    if NODE_ADDR not in AUTHENTICATED_NODES:
        request_whitelist_join(NODE_ADDR)
    while True:
        # 未同步完成/未加入白名单，不挖矿
        if not IS_FULLY_SYNCED:
            log_print(f"[等待] 同步中（本地高度{get_chain_height()}），暂不挖矿")
            time.sleep(10)
            continue
        if NODE_ADDR not in AUTHENTICATED_NODES:
            log_print(f"[等待] 未加入白名单，暂不挖矿（当前白名单节点数：{len(AUTHENTICATED_NODES)}）")
            time.sleep(30)
            request_whitelist_join(NODE_ADDR)
            continue
        time.sleep(60)  # 每分钟尝试出块一次
        with QUEUE_LOCK:
            if not GLOBAL_QUEUE:
                GLOBAL_QUEUE.extend(AUTHENTICATED_NODES)  # 白名单节点排队挖矿
            current_miner = GLOBAL_QUEUE[0]
        # 当前不是本节点挖矿，等待
        if current_miner != NODE_ADDR:
            log_print(f"[等待] 当前挖矿节点：{current_miner[:8]}...，本节点排队中")
            continue
        # 计算总发行量与合法奖励
        current_supply = get_total_supply()
        block_reward = REWARD if (current_supply + REWARD) <= TOTAL_SUPPLY_LIMIT else 0
        prev_height = get_chain_height()
        prev_block = get_block_from_full_chain(prev_height) if prev_height > 0 else None
        prev_hash = hashlib.sha256(json.dumps(asdict(prev_block)).encode()).hexdigest() if prev_block else "0"*64
        # 筛选有效交易
        with TX_POOL_LOCK:
            sorted_txs = sorted(TX_POOL, key=lambda x: (x["sender"], x["nonce"]))
        valid_txs = []
        for tx in sorted_txs:
            if not verify_tx_signature(tx):
                continue
            sender_bal = get_balance_from_cache(tx["sender"], prev_height)
            if sender_bal >= (tx["amount"] + FEE):
                valid_txs.append(tx)
        # 构建并保存区块
        blk = Block(
            height=prev_height + 1,
            prev_hash=prev_hash,
            miner=current_miner,
            txs=valid_txs,
            reward=block_reward
        )
        save_block_to_full_chain(blk)
        # 广播区块到所有P2P节点
        for peer_addr in P2P_PEERS:
            try:
                requests.post(f"http://{peer_addr}/json/submit_block", json=asdict(blk), timeout=8)
            except:
                continue
        # 更新挖矿队列和交易池
        with QUEUE_LOCK:
            GLOBAL_QUEUE.pop(0)
            GLOBAL_QUEUE.append(current_miner)
        with TX_POOL_LOCK:
            packed_hashes = {hashlib.sha256(json.dumps(tx, sort_keys=True).encode()).hexdigest() for tx in valid_txs}
            TX_POOL = [tx for tx in TX_POOL if hashlib.sha256(json.dumps(tx, sort_keys=True).encode()).hexdigest() not in packed_hashes]
        # 打印日志
        log_print(f"[合法出块] 高度#{blk.height} | 矿工{blk.miner[:8]}... | 奖励{blk.reward} | 交易数{len(valid_txs)}")

# ---------- HTTP请求处理器 ----------
class MainHandler(http.server.BaseHTTPRequestHandler):
    def send_json(self, data: Dict):
        """发送JSON响应"""
        self.send_response(200)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.end_headers()
        try:
            self.wfile.write(json.dumps(data).encode())
        except BrokenPipeError:
            pass

    def handle(self):
        """请求限流+全局并发控制"""
        # 全局并发限制
        if not GLOBAL_REQUEST_SEMAPHORE.acquire(blocking=False):
            self.send_response(503)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.end_headers()
            self.wfile.write(json.dumps({"status": "fail", "msg": "节点繁忙，请稍后重试"}).encode())
            return
        try:
            # 单IP限流逻辑
            client_ip = self.client_address[0]
            now = time.time()
            with IP_BIND_LOCK:
                if client_ip not in IP_REQUEST_COUNT:
                    IP_REQUEST_COUNT[client_ip] = (1, now)
                else:
                    count, last_reset = IP_REQUEST_COUNT[client_ip]
                    if now - last_reset > 60:
                        IP_REQUEST_COUNT[client_ip] = (1, now)
                    else:
                        if count >= REQUEST_LIMIT_PER_MINUTE:
                            self.send_response(429)
                            self.send_header("Content-Type", "application/json; charset=utf-8")
                            self.end_headers()
                            self.wfile.write(json.dumps({"status": "fail", "msg": "请求过于频繁"}).encode())
                            return
                        IP_REQUEST_COUNT[client_ip] = (count + 1, last_reset)
            super().handle()
        finally:
            GLOBAL_REQUEST_SEMAPHORE.release()

    def do_GET(self):
        """处理GET请求"""
        # 1. 链高查询
        if self.path == "/json/chain_height":
            height = get_chain_height()
            self.send_json({"height": height})
        # 2. 挖矿队列查询
        elif self.path == "/json/global_queue":
            with QUEUE_LOCK:
                self.send_json({"queue": GLOBAL_QUEUE})
        # 3. 单个区块查询
        elif self.path.startswith("/json/block/"):
            try:
                height = int(self.path.split("/")[-1])
                block = get_block_from_full_chain(height)
                if block:
                    self.send_json({"block": asdict(block), "status": "success"})
                else:
                    self.send_json({"status": "fail", "msg": "区块不存在"})
            except:
                self.send_json({"status": "fail", "msg": "参数错误"})
        # 4. P2P节点列表查询
        elif self.path == "/p2p/peers":
            with IP_BIND_LOCK:
                self.send_json({"local_main_addr": f"{CURRENT_NODE_PUBLIC_IP}:{PORT}", "peers": list(P2P_PEERS.keys())})
        # 5. 节点状态查询
        elif self.path == "/json/node_status":
            with IP_BIND_LOCK:
                peer_count = len(P2P_PEERS)
            status = {
                "node_addr": NODE_ADDR,
                "current_height": get_chain_height(),
                "p2p_peer_count": peer_count,
                "mining_status": "running" if IS_FULLY_SYNCED and NODE_ADDR in AUTHENTICATED_NODES else "waiting",
                "tx_pool_size": len(TX_POOL),
                "storage_mode": "full_chain",
                "address_format": f"{ADDRESS_PREFIX} + 32位哈希（共36位）",
                "whitelist_count": len(AUTHENTICATED_NODES),
                "is_authenticated": NODE_ADDR in AUTHENTICATED_NODES
            }
            self.send_json(status)
        # 6. 余额查询（基于全网共识）
        elif self.path.startswith("/json/query_balance?"):
            try:
                params = dict([p.split("=") for p in self.path.split("?")[1].split("&")])
                addr = params.get("addr", "")
                if not is_valid_address(addr):
                    self.send_json({"status": "fail", "msg": "地址格式无效（需36位RNDC前缀地址）"})
                    return
                max_height = get_chain_height()
                balance = get_balance_from_cache(addr, max_height)
                self.send_json({
                    "status": "success",
                    "addr": addr,
                    "balance": balance,
                    "chain_height": max_height,
                    "query_mode": "consensus"
                })
            except Exception as e:
                self.send_json({"status": "fail", "msg": f"查询失败：{str(e)}"})
        # 7. 白名单查询
        elif self.path == "/json/whitelist":
            self.send_json({
                "authenticated_nodes": list(AUTHENTICATED_NODES),
                "request_count": len(NODE_WHITELIST_REQUESTS)
            })
        # 404
        else:
            self.send_response(404)
            self.end_headers()

    def do_POST(self):
        """处理POST请求"""
        content_length = int(self.headers.get("Content-Length", 0))
        data = json.loads(self.rfile.read(content_length).decode())
        # 1. 区块提交
        if self.path == "/json/submit_block":
            try:
                block = Block(**data)
                current_max_height = get_chain_height()
                if block.height == current_max_height + 1 and is_valid_address(block.miner):
                    save_block_to_full_chain(block)
                    log_print(f"[接收] 高度{block.height}（矿工：{block.miner[:8]}...）")
                    self.send_json({"status": "success"})
                else:
                    self.send_json({"status": "fail", "msg": "区块高度无效或矿工地址格式错误"})
            except:
                self.send_json({"status": "fail", "msg": "区块格式错误"})
        # 2. 交易提交
        elif self.path == "/json/submit_tx":
            if not verify_tx_signature(data):
                self.send_json({"status": "fail", "msg": "交易签名无效或地址格式错误"})
                return
            with TX_POOL_LOCK:
                if len(TX_POOL) >= MAX_TX_POOL_SIZE:
                    TX_POOL.pop(0)
                    log_print(f"[交易池清理] 容量已满，移除最旧交易")
                TX_POOL.append(data)
            self.send_json({"status": "success", "msg": "交易已加入池"})
        # 3. 白名单加入请求（核心新增）
        elif self.path == "/json/whitelist/request":
            request_node = data.get("node_addr", "")
            requester = data.get("requester", "")
            if not is_valid_address(request_node) or not is_valid_address(requester):
                self.send_json({"status": "fail", "msg": "地址格式无效"})
                return
            if NODE_ADDR in AUTHENTICATED_NODES:
                approve_whitelist_request(request_node, NODE_ADDR)
                self.send_json({"status": "success", "msg": "已认可请求"})
            else:
                self.send_json({"status": "fail", "msg": "本节点未认证，无权认可"})
        # 4. 白名单更新同步（核心新增）
        elif self.path == "/json/whitelist/update":
            remote_nodes = data.get("authenticated_nodes", [])
            if isinstance(remote_nodes, list) and all(is_valid_address(node) for node in remote_nodes):
                sync_whitelist(remote_nodes)
                self.send_json({"status": "success", "msg": "白名单已同步"})
            else:
                self.send_json({"status": "fail", "msg": "白名单格式无效"})
        # 404
        else:
            self.send_response(404)
            self.end_headers()

# ---------- 启动P2P服务 ----------
def start_p2p_server():
    """启动P2P服务"""
    p2p_handler = MainHandler
    p2p_httpd = socketserver.TCPServer(("0.0.0.0", P2P_DISCOVERY_PORT), p2p_handler)
    log_print(f"[P2P] 服务启动：{P2P_DISCOVERY_PORT}端口")
    p2p_httpd.serve_forever()

# ---------- 退出处理 ----------
def exit_handler():
    """程序退出时清理资源"""
    with IP_BIND_LOCK:
        if NODE_ADDR in ADDR_IP_MAP:
            ip = ADDR_IP_MAP[NODE_ADDR]
            conn = sqlite3.connect(DB_FILE)
            cur = conn.cursor()
            cur.execute("DELETE FROM ip_addr_map WHERE addr=?", (NODE_ADDR,))
            conn.commit()
            conn.close()

# ---------- 主函数 ----------
if __name__ == "__main__":
    log_print("[Node] 开始初始化...（无算力+动态白名单+防篡改）")
    # 初始化数据库
    init_full_chain_db()
    # 校验本地数据完整性
    verify_local_chain_integrity()
    # 加载配置与钱包
    NODE_IP = get_local_ip()
    NODE_KEY, NODE_ADDR, ENCRYPTOR = init_wallet()
    load_ip_addr_map()
    load_p2p_peers()
    bind_ip_address(NODE_IP, NODE_ADDR)
    atexit.register(exit_handler)
    # 启动白名单清理线程
    whitelist_clean_thread = threading.Thread(target=clean_expired_whitelist, daemon=True)
    whitelist_clean_thread.start()
    # 启动核心服务线程
    log_print("\n[启动线程] 开始启动核心服务...")
    p2p_server_thread = threading.Thread(target=start_p2p_server, daemon=True)
    p2p_server_thread.start()
    p2p_discover_thread = threading.Thread(target=p2p_discover_loop, daemon=True)
    p2p_discover_thread.start()
    sync_thread = threading.Thread(target=sync_loop, daemon=True)
    sync_thread.start()
    miner_thread = threading.Thread(target=miner_loop, daemon=True)
    miner_thread.start()
    # 启动主服务
    main_handler = MainHandler
    main_httpd = socketserver.TCPServer(("0.0.0.0", PORT), main_handler)
    log_print(f"\n[*] 节点启动成功！（无算力+动态白名单）")
    log_print(f"[*] 主服务：{PORT}端口 | P2P服务：{P2P_DISCOVERY_PORT}端口")
    log_print(f"[*] 节点地址：{NODE_ADDR} | 账本文件：{DB_FILE}")
    log_print(f"[*] 白名单节点数：{len(AUTHENTICATED_NODES)} | 等待加入请求数：{len(NODE_WHITELIST_REQUESTS)}")
    main_httpd.serve_forever()
