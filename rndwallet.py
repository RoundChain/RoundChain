#!/usr/bin/env python3
"""RNDC区块链配套钱包：36位地址生成+余额查询+转账"""
import json
import hashlib
import requests
from nacl.signing import SigningKey, VerifyKey
import nacl.encoding
from cryptography.fernet import Fernet
import os
import time
from typing import Optional, Tuple

# -------------------------- 核心配置（对接你的节点） --------------------------
NODE_API_URL = "http://62.234.183.74:9755"  # 你的节点API地址
WALLET_DIR = "./rnd_wallet"  # 钱包文件存储目录
ENCRYPT_KEY_FILE = f"{WALLET_DIR}/encrypt_key.key"  # 加密密钥文件
# 36位地址配置（和节点一致）
ADDRESS_PREFIX = "RNDC"
ADDRESS_LENGTH = 36
# 过滤模糊字符（避免O/0、I/1混淆）
VALID_CHARS = "23456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"

# -------------------------- 工具函数 --------------------------
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
    return private_key, public_key, address

# -------------------------- 核心功能 --------------------------
def query_balance(address: str) -> Optional[int]:
    """查询地址余额（对接节点API）"""
    try:
        response = requests.get(f"{NODE_API_URL}/json/query_balance?addr={address}", timeout=10)
        if response.status_code == 200:
            data = response.json()
            if data["status"] == "success":
                print(f"\n📊 地址余额查询结果")
                print(f"地址：{address}")
                print(f"余额：{data['balance']} RNDC")
                print(f"当前链高：{data['chain_height']}")
                return data["balance"]
            else:
                print(f"❌ 查询失败：{data['msg']}")
        else:
            print(f"❌ 节点连接失败（状态码：{response.status_code}）")
    except Exception as e:
        print(f"❌ 查询异常：{str(e)}")
    return None

def transfer(
    private_key: SigningKey,
    public_key: str,
    from_address: str,
    to_address: str,
    amount: int,
    nonce: int = None
) -> bool:
    """发起转账（签名交易并提交到节点）"""
    # 校验参数
    if amount <= 0:
        print(f"❌ 转账金额必须大于0")
        return False
    if not to_address.startswith(ADDRESS_PREFIX) or len(to_address) != ADDRESS_LENGTH:
        print(f"❌ 接收地址格式无效（需36位RNDC前缀地址）")
        return False
    
    # 关键修改：手续费改为1 RNDC，校验余额是否足够（金额+手续费）
    FEE = 1  # 与节点手续费配置保持一致
    balance = query_balance(from_address)
    if balance is None or balance < (amount + FEE):
        print(f"❌ 余额不足！需 {amount + FEE} RNDC（金额{amount} + 手续费{FEE}），当前余额{balance}")
        return False
    
    # 自动生成nonce（防止交易重放）
    if nonce is None:
        nonce = int(time.time() * 1000)  # 毫秒级时间戳
    
    # 构建交易数据（不含签名）
    tx_data = {
        "sender": from_address,
        "recipient": to_address,
        "amount": amount,
        "public_key": public_key,
        "nonce": nonce,
        "timestamp": time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())
    }
    
    # 后续签名、提交逻辑不变...
    
    # 签名交易
    try:
        # 对排序后的交易数据签名（确保节点验证通过）
        sorted_tx_json = json.dumps(tx_data, sort_keys=True).encode()
        signature = private_key.sign(sorted_tx_json).signature.hex()
        tx_data["signature"] = signature
    except Exception as e:
        print(f"❌ 交易签名失败：{str(e)}")
        return False
    
    # 提交交易到节点
    try:
        response = requests.post(
            f"{NODE_API_URL}/json/submit_tx",
            json=tx_data,
            headers={"Content-Type": "application/json"},
            timeout=10
        )
        if response.status_code == 200:
            data = response.json()
            if data["status"] == "success":
                print(f"\n✅ 转账交易提交成功！")
                print(f"📝 交易详情：")
                print(f"   从：{from_address}")
                print(f"   到：{to_address}")
                print(f"   金额：{amount} RNDC")
                print(f"   Nonce：{nonce}")
                print(f"   状态：已加入交易池，等待打包")
                return True
            else:
                print(f"❌ 交易提交失败：{data['msg']}")
        else:
            print(f"❌ 节点响应失败（状态码：{response.status_code}）")
    except Exception as e:
        print(f"❌ 交易提交异常：{str(e)}")
    return False

# -------------------------- 交互界面 --------------------------
def wallet_cli():
    """钱包命令行交互界面"""
    print("=" * 50)
    print("📱 RNDC区块链钱包 v1.0（36位地址版）")
    print(f"📡 对接节点：{NODE_API_URL}")
    print("=" * 50)
    
    # 初始化加密器和钱包
    encryptor = init_wallet_dir()
    wallet = load_wallet(encryptor)
    
    if not wallet:
        print("\n⚠️  未检测到已存在的钱包，是否创建新钱包？")
        choice = input("请输入 y/n：").strip().lower()
        if choice != "y":
            print("❌ 退出钱包")
            return
        private_key, public_key, address = create_new_wallet(encryptor)
    else:
        private_key, public_key, address = wallet
        print(f"\n✅ 已加载钱包：")
        print(f"  address: {address}")
    
    # 主功能循环
    while True:
        print("\n" + "-" * 50)
        print("请选择功能：")
        print("1. 查询当前钱包余额")
        print("2. 发起转账")
        print("3. 查询指定地址余额")
        print("4. 退出钱包")
        print("-" * 50)
        choice = input("输入功能编号（1-4）：").strip()
        
        if choice == "1":
            # 查询当前钱包余额
            query_balance(address)
        
        elif choice == "2":
            # 发起转账
            print("\n📤 发起转账")
            to_addr = input("请输入接收地址（36位RNDC前缀）：").strip()
            try:
                amount = int(input("请输入转账金额（RNDC）：").strip())
            except ValueError:
                print("❌ 金额必须是整数")
                continue
            transfer(private_key, public_key, address, to_addr, amount)
        
        elif choice == "3":
            # 查询指定地址余额
            target_addr = input("请输入要查询的地址（36位RNDC前缀）：").strip()
            query_balance(target_addr)
        
        elif choice == "4":
            # 退出
            print("\n👋 退出钱包，感谢使用！")
            break
        
        else:
            print("❌ 无效选择，请输入1-4之间的编号")

if __name__ == "__main__":
    try:
        wallet_cli()
    except KeyboardInterrupt:
        print("\n\n👋 强制退出钱包")
    except Exception as e:
        print(f"\n❌ 钱包运行异常：{str(e)}")
