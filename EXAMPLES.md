# 使用示例 / Usage Examples

## 示例 1: 完整的备份流程

### 前置准备
- 准备 5 张 NTAG216 卡片（或 7 张，包括 2 张备用）
- 连接 ACR122U 读卡器到计算机
- 确保计算机已断网

### 步骤 1: 启动系统

**Linux/Mac:**
```bash
./start.sh
```

**Windows:**
```batch
start.bat
```

或直接运行:
```bash
python server.py
```

### 步骤 2: 访问 Web 界面

打开浏览器，访问: `http://127.0.0.1:8080`

### 步骤 3: 备份助记词

1. 在"备份助记词"标签页输入您的助记词:
```
abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about
```

2. 点击"开始备份"按钮

3. 系统会提示准备卡片，依次放置 5 张卡片：
   - 放置卡片 1，点击"写入卡片 1"
   - 等待写入完成
   - 取下卡片 1，放置卡片 2
   - 重复直到所有 5 张卡片写入完成

4. 确认所有卡片显示"已完成"状态

### 步骤 4: 标记卡片（可选）

在卡片背面使用铅笔轻轻标记卡片编号（1-5），便于管理。

**⚠️ 注意:** 不要在卡片上标记任何敏感信息，如"助记词"、"钱包"等。

### 步骤 5: 验证备份

1. 关闭浏览器（这会清空服务器内存）
2. 刷新页面或重新打开
3. 切换到"恢复助记词"标签页
4. 点击"开始恢复"
5. 依次放置任意 3 张卡片（例如卡片 1、3、5）
6. 验证恢复的助记词是否正确

### 步骤 6: 安全存储

将 5 张卡片分散存放在不同的安全位置：
- 家中保险箱: 卡片 1, 2
- 银行保险柜: 卡片 3
- 信任的亲友处: 卡片 4, 5（不同城市）

---

## 示例 2: 恢复助记词流程

假设您需要恢复助记词，手上有卡片 2、4、5。

### 步骤 1: 启动系统

```bash
python server.py
```

### 步骤 2: 打开恢复界面

访问 `http://127.0.0.1:8080`，切换到"恢复助记词"标签页。

### 步骤 3: 读取卡片

1. 点击"开始恢复"
2. 放置卡片 2，点击"读取卡片 1"
3. 等待读取完成，进度显示 1/3
4. 取下卡片 2，放置卡片 4
5. 点击"读取卡片 2"，进度显示 2/3
6. 取下卡片 4，放置卡片 5
7. 点击"读取卡片 3"
8. 系统自动恢复并显示助记词

### 步骤 4: 使用助记词

复制显示的助记词，导入到您的钱包软件。

**⚠️ 重要:** 恢复完成后立即：
- 关闭浏览器
- 清空浏览器缓存和历史记录
- 重启计算机（确保内存清空）

---

## 示例 3: 测试系统（无硬件）

您可以先运行核心功能测试，验证加密和分片功能：

```bash
python test_core.py
```

预期输出：
```
======================================================================
NFC Mnemonic Backup System - Core Functionality Tests
======================================================================

Testing AES-256-GCM encryption/decryption...
  ✓ Generated 256-bit key...
  ✓ Encrypted mnemonic...
  ✓ Decrypted successfully...
  ✓ Correctly rejects wrong key
✅ Encryption/Decryption test passed

Testing Shamir Secret Sharing (3-of-5)...
  ✓ Original key...
  ✓ Split into 5 shares
  ✓ Recovered key...
  ✓ Key matches original
✅ Shamir Secret Sharing test passed

...

✅ ALL TESTS PASSED!
```

---

## 示例 4: 使用不同的助记词长度

### 12 词助记词
```
witch collapse practice feed shame open despair creek road again ice least
```
加密后约 120 字节

### 15 词助记词
```
board flee heavy tunnel powder denial science ski answer betray cargo cat
```
加密后约 150 字节

### 18 词助记词
```
board flee heavy tunnel powder denial science ski answer betray cargo cat hammer
```
加密后约 180 字节

### 24 词助记词
```
abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon art
```
加密后约 215 字节

**所有长度都支持！** 系统会自动处理不同长度的助记词。

---

## 示例 5: 卡片更换检测

系统使用卡内数据识别卡片，而不是 UID：

1. 在恢复过程中，如果您尝试读取同一张卡片两次：
```
❌ 错误: 检测到相同的卡片，请更换不同的卡片
```

2. 系统通过比较以下数据判断卡片是否相同：
   - CardID (16 字节)
   - Counter (8 字节时间戳)
   - Challenge (32 字节随机值)

3. 只有当所有三个值都不同时，才认为是不同的卡片

---

## 常见问题 / FAQ

### Q: 如果丢失 3 张或更多卡片怎么办？
**A:** 无法恢复。这是设计的安全特性。请确保卡片分散存储。

### Q: 可以更改阈值吗（例如 2-of-5 或 4-of-5）？
**A:** 可以，修改代码中的 `threshold` 和 `shares` 参数。但需要重新备份。

### Q: 可以使用其他 NFC 卡片吗？
**A:** 可以使用 NTAG215（容量较小）进行测试。NTAG213 容量可能不足。推荐使用 NTAG216。

### Q: 系统支持哪些助记词标准？
**A:** 系统不验证助记词格式，您可以备份任何文本。建议使用 BIP39 标准助记词。

### Q: 数据在内存中保存多久？
**A:** 直到浏览器关闭或服务器重启。WebSocket 断开时会自动清空。

### Q: 可以在多台计算机上使用同一组卡片吗？
**A:** 可以。卡片是独立的，可以在任何安装了本系统的计算机上使用。

### Q: 如何验证系统安全性？
**A:** 
1. 审查源代码
2. 运行测试套件
3. 在隔离环境中测试
4. 请安全专家审计

### Q: 系统会记录日志吗？
**A:** 不会。所有操作都在内存中进行，不写入任何日志文件。

### Q: 如何彻底清除数据？
**A:** 
1. 关闭浏览器
2. 停止服务器（Ctrl+C）
3. 重启计算机
4. （可选）使用内存清理工具

### Q: 卡片可以重复使用吗？
**A:** 可以，但每次写入会覆盖之前的数据。建议使用新卡片进行重要备份。

### Q: 支持密码保护吗？
**A:** 当前版本不支持额外的密码保护。加密密钥通过 Shamir 分片保护。

---

## 高级用法

### 自定义阈值
编辑 `server.py`，找到:
```python
shares = self.crypto.split_key(aes_key, threshold=3, shares=5)
```

修改为所需的阈值，例如 2-of-5:
```python
shares = self.crypto.split_key(aes_key, threshold=2, shares=5)
```

或 4-of-7:
```python
shares = self.crypto.split_key(aes_key, threshold=4, shares=7)
```

### 批量备份
如果需要备份多个助记词，建议：
1. 使用不同的卡片组
2. 明确标记不同的备份组
3. 分别进行恢复测试

### 自动化测试
使用测试脚本验证系统功能：
```bash
# 运行所有测试
python test_core.py

# 测试加密
python -c "from server import CryptoManager; c = CryptoManager(); print('Test passed')"
```

---

## 故障排除

### 问题: 无法检测到读卡器
```bash
# Linux: 检查 PC/SC 服务
sudo systemctl status pcscd
sudo systemctl start pcscd

# 检查读卡器连接
pcsc_scan
```

### 问题: 卡片写入失败
1. 确认使用 NTAG216 卡片
2. 卡片放置平稳，不要移动
3. 清洁读卡器表面
4. 尝试不同的卡片

### 问题: 恢复失败
1. 确认至少使用 3 张不同的卡片
2. 确认卡片未损坏（尝试读取测试）
3. 确认使用的是同一组备份的卡片
4. 尝试不同的卡片组合

### 问题: 浏览器无法连接
1. 确认服务器正在运行
2. 检查端口 8080 未被占用
3. 确认访问 `127.0.0.1` 而非 `localhost`
4. 检查防火墙设置

---

## 更多信息

- 查看 `README.md` 了解系统概述
- 查看 `SECURITY.md` 了解安全注意事项
- 查看 `server.py` 源代码了解实现细节
- 运行 `python test_core.py` 进行功能测试
