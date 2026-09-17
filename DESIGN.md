# 06-安全 设计文档：minisec（mini 端口扫描器 + 变异模糊器）

## 参照
- projectdiscovery/naabu（6.2k★）：并发 TCP 端口扫描
- sec-tools/litefuzz：变异策略（位翻转、边界值、拼接）

**定位**：教育用途的安全工具重写，理解原语的实现，而不是替代生产工具。
仅用于授权测试场景；扫描器默认拒绝非私有网段目标（可用 `--allow-external` 显式解除）。

## 模块
### portscan.py — TCP connect 扫描器
- 线程池（默认 256 并发）+ `socket.connect_ex`，带超时
- 开放端口可选 banner 抓取（`recv` 1 行）
- 输入支持单主机、CIDR、端口范围 `1-1024` 或列表
- 私网/环回校验：`ipaddress.ip_address(target).is_private or is_loopback`

### fuzz.py — 变异式模糊器
对"以文件为输入的命令行目标"做覆盖率无关的黑盒变异：
- 种子队列 + 变异算子：位翻转（1/2/4 位）、字节随机、边界值注入（0x00/0xFF/0x7F/
  长度魔数）、块删除、块复制、种子拼接
- 每次运行子进程（timeout=2s），以**非零退出码或被信号杀死**为崩溃判据
- 崩溃样本去重保存（`crashes/`），附变异谱系
- 停止条件：迭代数或发现 N 个崩溃

### test_minisec.py — 离线自验证
- 扫描器：在本机开 3 个监听 socket（含 1 个发送 banner 的），扫描后必须全部命中，
  且随机关闭端口不误报
- 私网守卫：扫描公网 IP 应被拒绝
- 模糊器：构造一个"读到 CRASHTOKEN 就 abort"的 Python 假目标，
  断言模糊器在限定迭代内找到崩溃样本且样本确实触发

## 目录
```
06-security/
├── DESIGN.md
└── minisec/
    ├── portscan.py
    ├── fuzz.py
    └── test_minisec.py
```
