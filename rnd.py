#!/usr/bin/env python3
"""RND节点程序：多节点集群（9753/9754端口) - 全量存储+36位RNDC地址版"""
import json, time, hashlib, http.server, socketserver, sqlite3, threading, requests
from dataclasses import dataclass, asdict
from nacl.signing import SigningKey, VerifyKey
import nacl.encoding
from typing import List, Dict, Set, Optional, Tuple
import random
from cryptography.fernet import Fernet
import os
import socket
import atexit
# ---------- 节点核心配置（新增36位地址配置） ----------
PORT = 9754  # 主服务端口
DB_FILE = "node.db"  # 全量存储数据库
REWARD = 1280
TOTAL_SUPPLY_LIMIT = 12800000000
FEE = 1
TIMEOUT = 180
SYNC_INTERVAL = 10
P2P_DISCOVERY_PORT = 9753  # P2P端口
TX_SYNC_INTERVAL = 10
WALLET_DIR = "./rnd_wallet"  # 独立钱包目录
ENCRYPT_KEY_FILE = f"{WALLET_DIR}/encrypt_key.key"
CURRENT_NODE_PUBLIC_IP = "62.234.183.74"  # 节点1公网IP
P2P_SEEDS = ["82.157.37.13:9753"]  # 对等节点，可填写多个，用逗号隔开
MAX_TX_POOL_SIZE = 1000  # 交易池最大容量
REQUEST_LIMIT_PER_MINUTE = 100  # 单IP每分钟最大请求数
# 36位地址配置（RNDC前缀+32位哈希）
ADDRESS_PREFIX = "RNDC"
ADDRESS_LENGTH = 36  # 前缀4位 + 哈希32位 = 36位
#去除模糊数字与字母
VALID_CHARS = "23456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
IP_BIND_LOCK = threading.Lock()
# ---------- 全局变量（不变） ----------
NODE_ADDR = ""
NODE_KEY = None
ENCRYPTOR = None
NODE_IP = ""
P2P_PEERS = {}
GLOBAL_QUEUE = []
TX_POOL = []
REGISTERED_MINERS = set()
MINER_HEARTBEAT = {}
BALANCE_CACHE = {}  # {addr_maxheight: balance}
IP_ADDR_MAP = {}
ADDR_IP_MAP = {}
IP_REQUEST_COUNT = {}  # {ip: (count, last_reset_time)} 限流用
QUEUE_LOCK = threading.Lock()
TX_POOL_LOCK = threading.Lock()
IP_BIND_LOCK = threading.Lock()
IS_SYNCING = False
IS_TX_SYNCING = False
IS_FULLY_SYNCED = False
P2P_HEIGHT_CACHE = {}  # {peer_main_addr: (height, timestamp)}
GLOBAL_REQUEST_SEMAPHORE = threading.Semaphore(20) #全局最多20个并发请求，保证正常运行
# ---------- 核心数据结构（不变） ----------
@dataclass
class Block:
    height: int
    prev_hash: str
    miner: str
    txs: List[Dict]
    reward: int
# ---------- 工具函数（修改钱包地址生成逻辑） ----------
def log_print(msg: str):
    """带时间戳的日志打印函数"""
    timestamp = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())
    print(f"[{timestamp}] {msg}")
def get_local_ip() -> str:
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
    # 生成SHA256哈希，取足够长的字符用于过滤
    hash_hex = hashlib.sha256(public_key.encode()).hexdigest()[:64]
    # 过滤模糊字符，取前32位
    filtered_chars = [c for c in hash_hex if c in VALID_CHARS][:32]
    # 拼接前缀，确保36位
    address = f"{ADDRESS_PREFIX}{''.join(filtered_chars)}"
    if len(address) != ADDRESS_LENGTH:
        raise ValueError(f"地址生成失败：长度为{len(address)}位（预期36位）")
    return address

def load_wallet(encryptor: Fernet) -> Optional[Tuple[SigningKey, str, str]]:
    """加载已存在的钱包"""
    wallet_files = [f for f in os.listdir(WALLET_DIR) if f.startswith("rndc_wallet_") and f.endswith(".json")]
    if not wallet_files:
        return None
    # 加载第一个钱包（支持单钱包，如需多钱包可扩展）
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
    # 生成非对称密钥对
    private_key = SigningKey.generate()
    public_key = private_key.verify_key.encode(encoder=nacl.encoding.HexEncoder).decode()
    # 生成36位地址
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
    
    return private_key, public_key, address  # 返回3个值，匹配接收变量

def init_wallet() -> Tuple[SigningKey, str, Fernet]:
    """节点钱包初始化入口（加载已有/创建新钱包）"""
    # 初始化钱包目录和加密器
    encryptor = init_wallet_dir()
    # 尝试加载已有钱包
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
    with IP_BIND_LOCK:
        IP_ADDR_MAP[ip] = addr
        ADDR_IP_MAP[addr] = ip
        conn = sqlite3.connect(DB_FILE)
        cur = conn.cursor()
        cur.execute("CREATE TABLE IF NOT EXISTS ip_addr_map(ip TEXT PRIMARY KEY, addr TEXT)")
        cur.execute("INSERT OR REPLACE INTO ip_addr_map(ip, addr) VALUES (?, ?)", (ip, addr))
        conn.commit()
        conn.close()  # 补充关闭数据库连接
        
def load_ip_addr_map():
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
# ---------- 安全相关函数（新增36位地址验证） ----------
def is_valid_address(addr: str) -> bool:
    """验证地址是否为36位RNDC格式"""
    return len(addr) == ADDRESS_LENGTH and addr.startswith(ADDRESS_PREFIX)
def verify_tx_signature(tx: Dict) -> bool:
    """验证交易签名有效性（新增地址格式验证）"""
    required_fields = ["sender", "signature", "public_key", "amount", "recipient", "nonce"]
    if not all(field in tx for field in required_fields):
        log_print(f"[交易验证失败] 字段缺失")
        return False
    # 验证发送方和接收方地址格式
    if not is_valid_address(tx["sender"]) or not is_valid_address(tx["recipient"]):
        log_print(f"[交易验证失败] 地址格式无效（需36位RNDC前缀地址）")
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
# ---------- 区块相关函数（全量存储，新增地址验证） ----------
def init_full_chain_db():
    """初始化全量区块数据库"""
    conn = sqlite3.connect(DB_FILE)
    cur = conn.cursor()
    # 创建全量区块表
    cur.execute("""
        CREATE TABLE IF NOT EXISTS blocks (
            height INTEGER PRIMARY KEY,
            prev_hash TEXT NOT NULL,
            miner TEXT NOT NULL,
            txs TEXT NOT NULL,
            reward INTEGER NOT NULL,
            create_time REAL NOT NULL
        )
    """)
    conn.commit()
    conn.close()
def verify_block_chain(height: int) -> bool:
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
    """将区块保存到全量数据库（验证矿工地址格式）"""
    # 验证矿工地址
    if not is_valid_address(block.miner):
        log_print(f"[保存失败] 区块{block.height}矿工地址格式无效：{block.miner}")
        return
    conn = sqlite3.connect(DB_FILE)
    cur = conn.cursor()
    cur.execute("""
        INSERT OR REPLACE INTO blocks 
        (height, prev_hash, miner, txs, reward, create_time)
        VALUES (?, ?, ?, ?, ?, ?)
    """, (
        block.height,
        block.prev_hash,
        block.miner,
        json.dumps(block.txs),
        block.reward,
        time.time()
    ))
    conn.commit()
    conn.close()
    log_print(f"[全量存储] 区块{block.height}已保存（矿工：{block.miner[:8]}...）")
    # 清理所有相关地址的余额缓存（矿工+所有交易的发送方/接收方）
    with IP_BIND_LOCK:
        cache_keys = list(BALANCE_CACHE.keys())
        related_addrs = {block.miner}
        for tx in block.txs:
            if tx.get("sender"):
                related_addrs.add(tx["sender"])
            if tx.get("recipient"):
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
# ---------- P2P同步相关函数（不变） ----------
def save_p2p_peer(peer_main_addr: str):
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
        
        # 清理无效节点（超时+不可达）
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
    """区块同步（适配全量存储，优化请求频率+限流适配）"""
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
            log_print(f"♻️[同步] P2P最高{p2p_max_height} > 本地{local_max_height}，开始同步（限速模式）")
            # 新增：每同步10个区块暂停10秒，避免触发限流
            batch_size = 10
            for batch_start in range(local_max_height + 1, p2p_max_height + 1, batch_size):
                batch_end = min(batch_start + batch_size - 1, p2p_max_height)
                log_print(f"♻️[批次同步] 开始同步区块 {batch_start}-{batch_end}")
                for height in range(batch_start, batch_end + 1):
                    block = None
                    retry_count = 0
                    while retry_count < 3 and not block:
                        for peer_main_addr in valid_p2p_nodes:
                            try:
                                # 新增：请求前延迟0.5秒，降低请求频率
                                time.sleep(0.5)
                                resp = requests.get(f"http://{peer_main_addr}/json/block/{height}", timeout=20)  # 超时延长至20秒
                                if resp.status_code == 429:
                                    log_print(f"♻️[限流触发] 节点{peer_main_addr}请求频繁，暂停30秒")
                                    time.sleep(30)
                                    continue
                                if resp.status_code == 200:
                                    block = Block(**resp.json()["block"])
                                    break
                            except requests.exceptions.Timeout:
                                log_print(f"♻️[请求超时] 区块{height}，切换节点重试")
                                continue
                            except Exception as e:
                                continue
                        retry_count += 1
                    if block:
                        save_block_to_full_chain(block)
                        log_print(f"♻️ [同步成功] 高度{height}")
                    else:
                        log_print(f"♻️[同步失败] 高度{height}（已重试3次）")
                # 新增：每批同步完成后暂停10秒，给对等节点减压
                time.sleep(10)
            local_max_height = get_chain_height()
        IS_FULLY_SYNCED = local_max_height >= p2p_max_height
        status = "完成" if IS_FULLY_SYNCED else "中"
        log_print(f"♻️[同步{status}] 本地{local_max_height} | 集群{p2p_max_height}")
    finally:
        IS_SYNCING = False
                  
        
def sync_loop():
    while True:
        sync_missing_blocks_from_peers()
        time.sleep(SYNC_INTERVAL)
# ---------- 挖矿相关函数（适配36位地址，修复余额计算） ----------
def get_balance_from_cache(addr: str, max_height: int) -> int:
    """按36位地址+最大高度缓存余额（修复异常处理）"""
    # 先验证地址格式
    if not is_valid_address(addr):
        log_print(f"[余额计算失败] 地址格式无效：{addr}")
        return 0
    cache_key = f"{addr}_{max_height}"
    if cache_key in BALANCE_CACHE:
        return BALANCE_CACHE[cache_key]
    
    balance = 0
    try:
        # 遍历全量区块计算余额（包含所有已确认区块）
        for height in range(1, max_height + 1):
            block = get_block_from_full_chain(height)
            if not block:
                continue
            # 累加矿工奖励
            if block.miner == addr:
                balance += block.reward
            # 处理交易：发送方减金额+手续费，接收方加金额
            for tx in block.txs:
                if tx.get("sender") == addr:
                    balance = max(0, balance - (tx["amount"] + FEE))  # 防止余额为负
                if tx.get("recipient") == addr:
                    balance += tx["amount"]
    except Exception as e:
        log_print(f"[错误] 计算地址{addr[:8]}...余额失败：{e}")
        balance = 0
    
    # 缓存结果（确保余额非负）
    BALANCE_CACHE[cache_key] = max(balance, 0)
    return BALANCE_CACHE[cache_key]
def miner_loop():
    global IS_FULLY_SYNCED, TX_POOL
    while True:
        if not IS_FULLY_SYNCED:
            log_print(f"[等待] ♻️同步中（本地高度{get_chain_height()}）")
            time.sleep(10)
            continue
        time.sleep(60)
        with QUEUE_LOCK:
            if not GLOBAL_QUEUE:
                GLOBAL_QUEUE.append(NODE_ADDR)
            current_miner = GLOBAL_QUEUE[0]
        # 验证矿工地址格式
        if not is_valid_address(current_miner):
            log_print(f"[挖矿跳过] 矿工地址格式无效：{current_miner}")
            with QUEUE_LOCK:
                GLOBAL_QUEUE.pop(0)
            continue
        if current_miner != NODE_ADDR and current_miner not in REGISTERED_MINERS:
            log_print(f"[等待] 当前：{current_miner[:8]}...")
            continue
        
        # 优化总发行量计算（从数据库查询，避免重复遍历）
        current_supply = 0
        try:
            conn = sqlite3.connect(DB_FILE)
            cur = conn.cursor()
            cur.execute("SELECT SUM(reward) FROM blocks")
            row = cur.fetchone()
            conn.close()
            current_supply = row[0] if row[0] is not None else 0
        except Exception as e:
            log_print(f"[错误] 计算总发行量失败：{e}")
            # 降级方案：遍历全量区块
            max_height = get_chain_height()
            for height in range(1, max_height + 1):
                block = get_block_from_full_chain(height)
                if block:
                    current_supply += block.reward
        
        block_reward = REWARD if (current_supply + REWARD) <= TOTAL_SUPPLY_LIMIT else 0
        prev_height = get_chain_height()
        prev_block = get_block_from_full_chain(prev_height) if prev_height > 0 else None
        prev_hash = hashlib.sha256(json.dumps(asdict(prev_block)).encode()).hexdigest() if prev_block else "0"*64
        
        with TX_POOL_LOCK:
            sorted_txs = sorted(TX_POOL, key=lambda x: (x["sender"], x["nonce"]))
        valid_txs = []
        for tx in sorted_txs:
            # 验证交易地址格式+余额充足
            if not is_valid_address(tx["sender"]) or not is_valid_address(tx["recipient"]):
                log_print(f"[交易过滤] 地址格式无效：{tx['sender'][:8]}...")
                continue
            sender_bal = get_balance_from_cache(tx["sender"], prev_height)
            if sender_bal >= (tx["amount"] + FEE):
                valid_txs.append(tx)
        
        # 构建并保存新块
        blk = Block(height=prev_height + 1, prev_hash=prev_hash, miner=current_miner, txs=valid_txs, reward=block_reward)
        save_block_to_full_chain(blk)
        
        # 同步到P2P节点
        for peer_main_addr in P2P_PEERS:
            try:
                requests.post(f"http://{peer_main_addr}/json/submit_block", json=asdict(blk), timeout=8)
            except:
                continue
        
        # 更新队列和交易池
        with QUEUE_LOCK:
            GLOBAL_QUEUE.pop(0)
            GLOBAL_QUEUE.append(current_miner)
        with TX_POOL_LOCK:
            packed_hashes = {hashlib.sha256(json.dumps(tx, sort_keys=True).encode()).hexdigest() for tx in valid_txs}
            TX_POOL = [tx for tx in TX_POOL if hashlib.sha256(json.dumps(tx, sort_keys=True).encode()).hexdigest() not in packed_hashes]
        
        mode = "单节点" if len(P2P_PEERS) == 0 else "多节点"
        log_print(f"[{mode}出块] 高度#{blk.height} | 矿工{current_miner[:8]}... | 奖励{block_reward} | 交易数{len(valid_txs)}")
# ---------- HTTP请求处理器（适配36位地址，新增余额查询接口） ----------
class MainHandler(http.server.BaseHTTPRequestHandler):
    def send_json(self, data: Dict):
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
            GLOBAL_REQUEST_SEMAPHORE.release() #释放并发锁
      
    def do_GET(self):
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
                "mining_status": "running" if IS_FULLY_SYNCED else "waiting_sync",
                "tx_pool_size": len(TX_POOL),
                "storage_mode": "full_chain",
                "address_format": f"{ADDRESS_PREFIX} + 32位哈希（共36位）",
                "last_sync_time": time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())
            }
            self.send_json(status)
        # 6. 缓存余额查询
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
                    "query_mode": "cache"
                })
            except Exception as e:
                self.send_json({"status": "fail", "msg": f"查询失败：{str(e)}"})
        # 7. 直接余额查询（跳过缓存，用于验证）
        elif self.path.startswith("/json/query_balance_direct?"):
            try:
                params = dict([p.split("=") for p in self.path.split("?")[1].split("&")])
                addr = params.get("addr", "")
                if not is_valid_address(addr):
                    self.send_json({"status": "fail", "msg": "地址格式无效（需36位RNDC前缀地址）"})
                    return
                max_height = get_chain_height()
                balance = 0
                # 直接遍历区块计算
                for height in range(1, max_height + 1):
                    block = get_block_from_full_chain(height)
                    if not block:
                        continue
                    if block.miner == addr:
                        balance += block.reward
                    for tx in block.txs:
                        if tx.get("sender") == addr:
                            balance = max(0, balance - (tx["amount"] + FEE))
                        if tx.get("recipient") == addr:
                            balance += tx["amount"]
                self.send_json({
                    "status": "success",
                    "addr": addr,
                    "balance": balance,
                    "chain_height": max_height,
                    "query_mode": "direct"
                })
            except Exception as e:
                self.send_json({"status": "fail", "msg": f"查询失败：{str(e)}"})
        # 404
        else:
            self.send_response(404)
            self.end_headers()
    def do_POST(self):
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
        # 404
        else:
            self.send_response(404)
            self.end_headers()
# ---------- 启动P2P服务（不变） ----------
def start_p2p_server():
    p2p_handler = MainHandler
    p2p_httpd = socketserver.TCPServer(("0.0.0.0", P2P_DISCOVERY_PORT), p2p_handler)
    log_print(f"[P2P] 服务启动：{P2P_DISCOVERY_PORT}端口")
    p2p_httpd.serve_forever()
# ---------- 退出处理（不变） ----------
def exit_handler():
    with IP_BIND_LOCK:
        if NODE_ADDR in ADDR_IP_MAP:
            ip = ADDR_IP_MAP[NODE_ADDR]
            conn = sqlite3.connect(DB_FILE)
            cur = conn.cursor()
            cur.execute("DELETE FROM ip_addr_map WHERE addr=?", (NODE_ADDR,))
            conn.commit()
            conn.close()
# ---------- 主函数（不变） ----------
if __name__ == "__main__":
    log_print("[Node] 开始初始化...（全量存储+36位RNDC地址）")
    # 初始化全量区块数据库
    init_full_chain_db()
    # 加载配置
    NODE_IP = get_local_ip()
    NODE_KEY, NODE_ADDR, ENCRYPTOR = init_wallet()
    load_ip_addr_map()
    load_p2p_peers()
    bind_ip_address(NODE_IP, NODE_ADDR)
    atexit.register(exit_handler)
    
    # 启动核心线程
    log_print("\n[启动线程] 开始启动核心服务...")
    # P2P服务线程
    p2p_server_thread = threading.Thread(target=start_p2p_server, daemon=True)
    p2p_server_thread.start()
    # P2P发现线程
    p2p_discover_thread = threading.Thread(target=p2p_discover_loop, daemon=True)
    p2p_discover_thread.start()
    # 同步线程
    sync_thread = threading.Thread(target=sync_loop, daemon=True)
    sync_thread.start()
    # 挖矿线程
    miner_thread = threading.Thread(target=miner_loop, daemon=True)
    miner_thread.start()
    
    # 启动主服务
    main_handler = MainHandler
    main_httpd = socketserver.TCPServer(("0.0.0.0", PORT), main_handler)
    log_print(f"\n[*] 节点启动成功！（全量存储+36位RNDC地址）")
    log_print(f"[*] 主服务：{PORT}端口 | P2P服务：{P2P_DISCOVERY_PORT}端口")
    log_print(f"[*] 节点地址：{NODE_ADDR} | 账本文件：{DB_FILE}")
    log_print(f"[*] 地址格式：{ADDRESS_PREFIX} + 32位哈希（共36位）")
    main_httpd.serve_forever()
