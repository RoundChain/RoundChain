

<!--
**RoundChain**

RNDC公网P2P节点程序（Python实现）
硬币总量  128亿
区块时间  60秒
每块奖励  1280
区块算法  轮流
已有地址 62.234.183.74， 82.157.37.13
1️⃣创建虚拟环境（myenv）
2️⃣安装依赖（pynacl cryptography requests psutil）
3️⃣开放端口
sudo ufw allow 9753/tcp
sudo ufw allow 9754/tcp
4️⃣重启防火墙生效
sudo ufw reload
5️⃣查看端口开放状态（确认已生效）
sudo ufw status
6️⃣核心配置修改
CURRENT_NODE_PUBLIC_IP = "你的公网IP"  # 替换为服务器公网IP（如123.45.67.89）
P2P_SEEDS = ["123.45.67.89:9753"]  # 对等节点，可添加多个（用逗号分隔）
PORT = 9754  # 主服务端口
P2P_DISCOVERY_PORT = 9753  # P2P端口（需与种子节点端口一致）
DB_FILE = "node.db"  # 数据库文件（可自定义jinx.db,zed.db etc...)
7️⃣激活虚拟环境
8️⃣下载rnd.py和rndwallet.py
9️⃣启动节点
python rnd.py

-->
