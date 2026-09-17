# minisec — 教育向安全工具重写

参照 [projectdiscovery/naabu](https://github.com/projectdiscovery/naabu) 与
[sec-tools/litefuzz](https://github.com/sec-tools/litefuzz) 的核心思路，
纯标准库实现，仅用于授权测试与学习。

## portscan.py — TCP connect 扫描器
- 线程池并发（默认 256）+ `connect_ex` + 超时
- 主机：单 IP / 域名；端口：`80` / `1-1024` / `80,443,8000-8100`
- 可选 banner 抓取
- **安全守卫**：目标必须解析到环回/私有地址，否则拒绝（`allow_external=True` 显式解除）；
  DNS 解析后再校验，发包前拦截

## fuzz.py — 变异式文件模糊器
- 变异算子：位翻转 / 字节随机 / 边界值注入 / 块删除 / 块复制 / 种子拼接
- **字典注入**（AFL 式）：魔数 token 无法靠盲变异凭空合成，需提供词典
- 崩溃判据：非零退出码或超时；样本按 SHA256 去重落盘，可回放
- 种子可复现（`random.Random(seed)`，刻意不用 secrets：模糊实验需要可复现而非加密随机）

## 验证（全离线）
```bash
python -m minisec.test_minisec
```
扫描器：本机开 3 个监听（其一发 banner）→ 全部命中且不误报关闭端口；
守卫：公网 IP 在发包前被拒。模糊器：对"含 CRASHTOKEN 即 abort"的假目标，
带词典在限定迭代内找到崩溃样本，且样本回放确实触发。
