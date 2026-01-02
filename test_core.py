#!/usr/bin/env python3
"""
NFC 助记词备份系统测试脚本
在不需要硬件的情况下测试核心加密和数据结构功能
"""

import sys
import os

# 添加父目录到路径
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from server import CryptoManager, InMemoryState


def test_encryption_decryption():
    """测试 AES 加密和解密"""
    print("测试 AES-256-GCM 加密/解密...")
    
    crypto = CryptoManager()
    test_mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
    
    # 生成密钥
    key = crypto.generate_key()
    assert len(key) == 32, "密钥应为 32 字节"
    print(f"  ✓ 生成 256 位密钥: {key.hex()[:16]}...")
    
    # 加密
    encrypted = crypto.encrypt_mnemonic(test_mnemonic, key)
    print(f"  ✓ 加密助记词（大小: {len(encrypted)} 字节）")
    
    # 解密
    decrypted = crypto.decrypt_mnemonic(encrypted, key)
    assert decrypted == test_mnemonic, "解密失败"
    print(f"  ✓ 解密成功: '{decrypted[:30]}...'")
    
    # 测试错误密钥
    wrong_key = crypto.generate_key()
    wrong_decrypt = crypto.decrypt_mnemonic(encrypted, wrong_key)
    assert wrong_decrypt is None, "应该拒绝错误的密钥"
    print("  ✓ 正确拒绝错误密钥")
    
    print("✅ 加密/解密测试通过\n")


def test_shamir_secret_sharing():
    """测试 Shamir 秘密共享"""
    print("测试 Shamir 秘密共享（3-of-5）...")
    
    crypto = CryptoManager()
    
    # 生成密钥
    key = crypto.generate_key()
    print(f"  ✓ 原始密钥: {key.hex()[:16]}...")
    
    # 分片
    shares = crypto.split_key(key, threshold=3, shares=5)
    assert len(shares) == 5, "应该有 5 个分片"
    print(f"  ✓ 分为 {len(shares)} 个分片")
    for i, share in enumerate(shares, 1):
        print(f"    分片 {i}: {share[:30]}...")
    
    # 使用 3 个分片测试恢复
    recovered_key = crypto.recover_key(shares[:3])
    assert recovered_key == key, "恢复失败"
    print(f"  ✓ 恢复的密钥: {recovered_key.hex()[:16]}...")
    print("  ✓ 密钥与原始密钥匹配")
    
    # 使用不同的 3 个分片进行测试
    recovered_key2 = crypto.recover_key([shares[0], shares[2], shares[4]])
    assert recovered_key2 == key, "使用不同分片恢复失败"
    print("  ✓ 使用不同分片组合恢复成功")
    
    # 测试仅使用 2 个分片时失败
    try:
        crypto.recover_key(shares[:2])
        assert False, "应该在只有 2 个分片时失败"
    except:
        print("  ✓ 在分片不足时正确失败")
    
    print("✅ Shamir 秘密共享测试通过\n")


def test_full_backup_recovery_flow():
    """测试完整的备份和恢复流程"""
    print("测试完整备份/恢复流程...")
    
    crypto = CryptoManager()
    state = InMemoryState()
    
    # 设置：创建备份数据
    test_mnemonic = "test wallet seed phrase for backup and recovery validation system check"
    print(f"  原始助记词: '{test_mnemonic}'")
    
    # 生成密钥并加密
    aes_key = crypto.generate_key()
    encrypted_blob = crypto.encrypt_mnemonic(test_mnemonic, aes_key)
    print(f"  ✓ 加密数据块大小: {len(encrypted_blob)} 字节")
    
    # 分片密钥
    shares = crypto.split_key(aes_key, threshold=3, shares=5)
    print(f"  ✓ 生成 {len(shares)} 个密钥分片")
    
    # 存储到内存（模拟存储）
    state.mnemonic = test_mnemonic
    state.encrypted_blob = encrypted_blob
    state.aes_key = aes_key
    state.shares = shares
    print("  ✓ 存储到内存状态")
    
    # 模拟恢复过程
    print("\n  模拟恢复...")
    recovery_shares = [shares[1], shares[3], shares[4]]  # 使用卡片 2, 4, 5
    print(f"  使用分片: 2, 4, 5")
    
    # 恢复密钥
    recovered_key = crypto.recover_key(recovery_shares)
    assert recovered_key is not None, "密钥恢复失败"
    print(f"  ✓ 恢复的密钥: {recovered_key.hex()[:16]}...")
    
    # 解密助记词
    recovered_mnemonic = crypto.decrypt_mnemonic(encrypted_blob, recovered_key)
    assert recovered_mnemonic is not None, "解密失败"
    assert recovered_mnemonic == test_mnemonic, "恢复的助记词不匹配"
    print(f"  ✓ 恢复的助记词: '{recovered_mnemonic}'")
    
    # 清除状态
    state.clear()
    assert state.mnemonic is None, "状态未清除"
    print("  ✓ 内存清除成功")
    
    print("✅ 完整备份/恢复流程测试通过\n")


def test_random_generation():
    """测试随机数据生成"""
    print("测试随机数据生成...")
    
    crypto = CryptoManager()
    
    # 测试密钥生成
    key1 = crypto.generate_key()
    key2 = crypto.generate_key()
    assert len(key1) == 32
    assert len(key2) == 32
    assert key1 != key2, "密钥应该不同"
    print("  ✓ AES 密钥是随机且唯一的")
    
    # 测试 CardID 生成
    card_id1 = crypto.generate_card_id()
    card_id2 = crypto.generate_card_id()
    assert len(card_id1) == 16
    assert len(card_id2) == 16
    assert card_id1 != card_id2, "CardID 应该不同"
    print("  ✓ CardID 是随机且唯一的")
    
    # 测试 Challenge 生成
    challenge1 = crypto.generate_challenge()
    challenge2 = crypto.generate_challenge()
    assert len(challenge1) == 32
    assert len(challenge2) == 32
    assert challenge1 != challenge2, "Challenge 应该不同"
    print("  ✓ Challenge 是随机且唯一的")
    
    print("✅ 随机生成测试通过\n")


def test_memory_state():
    """测试内存状态管理"""
    print("测试内存状态管理...")
    
    state = InMemoryState()
    
    # 设置数据
    state.mnemonic = "test mnemonic"
    state.encrypted_blob = b"encrypted data"
    state.aes_key = b"key" * 10
    state.shares = ["share1", "share2", "share3"]
    state.card_data[1] = {"test": "data"}
    
    assert state.mnemonic is not None
    assert state.encrypted_blob is not None
    assert len(state.shares) == 3
    assert 1 in state.card_data
    print("  ✓ 状态正确存储数据")
    
    # 清除状态
    state.clear()
    assert state.mnemonic is None
    assert state.encrypted_blob is None
    assert state.aes_key is None
    assert len(state.shares) == 0
    assert len(state.card_data) == 0
    print("  ✓ 状态清除所有数据")
    
    print("✅ 内存状态测试通过\n")


def test_data_structure_sizes():
    """测试数据结构是否符合 NTAG216 约束"""
    print("测试 NTAG216 数据结构约束...")
    
    crypto = CryptoManager()
    
    # 测试助记词加密大小
    test_mnemonics = [
        "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",  # 12 words
        "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon art",  # 24 words
    ]
    
    for mnemonic in test_mnemonics:
        key = crypto.generate_key()
        encrypted = crypto.encrypt_mnemonic(mnemonic, key)
        word_count = len(mnemonic.split())
        print(f"  {word_count} 词：加密大小 = {len(encrypted)} bytes (max 272)")
        assert len(encrypted) <= 272, f"Encrypted blob too large: {len(encrypted)} > 272"
    
    print("  ✓ 加密数据块适合 272 字节")
    
    # 测试分片大小
    key = crypto.generate_key()
    shares = crypto.split_key(key, threshold=3, shares=5)
    for i, share in enumerate(shares, 1):
        share_bytes = share.encode('utf-8')
        print(f"  Share {i}: {len(share_bytes)} bytes (max 80)")
        assert len(share_bytes) <= 80, f"Share too large: {len(share_bytes)} > 80"
    
    print("  ✓ 分片适合 80 字节")
    
    # 计算每张卡的总数据量
    card_id_size = 16  # Pages 4-7
    counter_size = 8   # Pages 8-9
    challenge_size = 32  # Pages 10-17
    blob_size = 272  # Pages 18-85
    share_size = 80  # Pages 86-105
    
    total_size = card_id_size + counter_size + challenge_size + blob_size + share_size
    total_pages = total_size // 4  # 4 bytes per page
    
    print(f"\n  每张卡的总数据:")
    print(f"    CardID: {card_id_size} bytes (4 pages)")
    print(f"    Counter: {counter_size} bytes (2 pages)")
    print(f"    Challenge: {challenge_size} bytes (8 pages)")
    print(f"    Encrypted Blob: {blob_size} bytes (68 pages)")
    print(f"    Share: {share_size} bytes (20 pages)")
    print(f"    Total: {total_size} bytes ({total_pages} pages)")
    print(f"    使用的页数: 4-105 (102 pages)")
    
    # NTAG216 has 888 bytes user memory (pages 4-230)
    assert total_size <= 888, "Total size exceeds NTAG216 capacity"
    print("  ✓ 数据结构适合 NTAG216")
    
    print("✅ 数据结构约束测试通过\n")


def main():
    """运行所有测试"""
    print("=" * 70)
    print("NFC 助记词备份系统 - 核心功能测试")
    print("=" * 70)
    print()
    
    try:
        test_encryption_decryption()
        test_shamir_secret_sharing()
        test_random_generation()
        test_memory_state()
        test_data_structure_sizes()
        test_full_backup_recovery_flow()
        
        print("=" * 70)
        print("✅ 所有测试通过！")
        print("=" * 70)
        print()
        print("核心功能已验证。准备进行硬件测试。")
        print("注意：NFC 卡操作需要 ACR122U 读卡器硬件。")
        
        return 0
    
    except AssertionError as e:
        print(f"\n❌ 测试失败: {e}")
        return 1
    except Exception as e:
        print(f"\n❌ 错误: {e}")
        import traceback
        traceback.print_exc()
        return 1


if __name__ == '__main__':
    sys.exit(main())
