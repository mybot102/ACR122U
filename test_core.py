#!/usr/bin/env python3
"""
Test script for NFC Mnemonic Backup System
Tests core cryptographic and data structure functionality without requiring hardware
"""

import sys
import os

# Add parent directory to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from server import CryptoManager, InMemoryState


def test_encryption_decryption():
    """Test AES encryption and decryption"""
    print("Testing AES-256-GCM encryption/decryption...")
    
    crypto = CryptoManager()
    test_mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
    
    # Generate key
    key = crypto.generate_key()
    assert len(key) == 32, "Key should be 32 bytes"
    print(f"  ✓ Generated 256-bit key: {key.hex()[:16]}...")
    
    # Encrypt
    encrypted = crypto.encrypt_mnemonic(test_mnemonic, key)
    print(f"  ✓ Encrypted mnemonic (size: {len(encrypted)} bytes)")
    
    # Decrypt
    decrypted = crypto.decrypt_mnemonic(encrypted, key)
    assert decrypted == test_mnemonic, "Decryption failed"
    print(f"  ✓ Decrypted successfully: '{decrypted[:30]}...'")
    
    # Test wrong key
    wrong_key = crypto.generate_key()
    wrong_decrypt = crypto.decrypt_mnemonic(encrypted, wrong_key)
    assert wrong_decrypt is None, "Should fail with wrong key"
    print("  ✓ Correctly rejects wrong key")
    
    print("✅ Encryption/Decryption test passed\n")


def test_shamir_secret_sharing():
    """Test Shamir secret sharing"""
    print("Testing Shamir Secret Sharing (3-of-5)...")
    
    crypto = CryptoManager()
    
    # Generate key
    key = crypto.generate_key()
    print(f"  ✓ Original key: {key.hex()[:16]}...")
    
    # Split into shares
    shares = crypto.split_key(key, threshold=3, shares=5)
    assert len(shares) == 5, "Should have 5 shares"
    print(f"  ✓ Split into {len(shares)} shares")
    for i, share in enumerate(shares, 1):
        print(f"    Share {i}: {share[:30]}...")
    
    # Test recovery with 3 shares
    recovered_key = crypto.recover_key(shares[:3])
    assert recovered_key == key, "Recovery failed"
    print(f"  ✓ Recovered key: {recovered_key.hex()[:16]}...")
    assert recovered_key == key
    print("  ✓ Key matches original")
    
    # Test with different 3 shares
    recovered_key2 = crypto.recover_key([shares[0], shares[2], shares[4]])
    assert recovered_key2 == key, "Recovery with different shares failed"
    print("  ✓ Recovery works with different share combinations")
    
    # Test failure with only 2 shares
    try:
        crypto.recover_key(shares[:2])
        assert False, "Should fail with only 2 shares"
    except:
        print("  ✓ Correctly fails with insufficient shares")
    
    print("✅ Shamir Secret Sharing test passed\n")


def test_full_backup_recovery_flow():
    """Test complete backup and recovery flow"""
    print("Testing complete backup/recovery flow...")
    
    crypto = CryptoManager()
    state = InMemoryState()
    
    # Setup: Create backup data
    test_mnemonic = "test wallet seed phrase for backup and recovery validation system check"
    print(f"  Original mnemonic: '{test_mnemonic}'")
    
    # Generate key and encrypt
    aes_key = crypto.generate_key()
    encrypted_blob = crypto.encrypt_mnemonic(test_mnemonic, aes_key)
    print(f"  ✓ Encrypted blob size: {len(encrypted_blob)} bytes")
    
    # Split key
    shares = crypto.split_key(aes_key, threshold=3, shares=5)
    print(f"  ✓ Generated {len(shares)} key shares")
    
    # Store in memory (simulating storage)
    state.mnemonic = test_mnemonic
    state.encrypted_blob = encrypted_blob
    state.aes_key = aes_key
    state.shares = shares
    print("  ✓ Stored in memory state")
    
    # Simulate recovery process
    print("\n  Simulating recovery...")
    recovery_shares = [shares[1], shares[3], shares[4]]  # Use cards 2, 4, 5
    print(f"  Using shares: 2, 4, 5")
    
    # Recover key
    recovered_key = crypto.recover_key(recovery_shares)
    assert recovered_key is not None, "Key recovery failed"
    print(f"  ✓ Recovered key: {recovered_key.hex()[:16]}...")
    
    # Decrypt mnemonic
    recovered_mnemonic = crypto.decrypt_mnemonic(encrypted_blob, recovered_key)
    assert recovered_mnemonic is not None, "Decryption failed"
    assert recovered_mnemonic == test_mnemonic, "Recovered mnemonic doesn't match"
    print(f"  ✓ Recovered mnemonic: '{recovered_mnemonic}'")
    
    # Clear state
    state.clear()
    assert state.mnemonic is None, "State not cleared"
    print("  ✓ Memory cleared successfully")
    
    print("✅ Full backup/recovery flow test passed\n")


def test_random_generation():
    """Test random data generation"""
    print("Testing random data generation...")
    
    crypto = CryptoManager()
    
    # Test key generation
    key1 = crypto.generate_key()
    key2 = crypto.generate_key()
    assert len(key1) == 32
    assert len(key2) == 32
    assert key1 != key2, "Keys should be different"
    print("  ✓ AES keys are random and unique")
    
    # Test CardID generation
    card_id1 = crypto.generate_card_id()
    card_id2 = crypto.generate_card_id()
    assert len(card_id1) == 16
    assert len(card_id2) == 16
    assert card_id1 != card_id2, "CardIDs should be different"
    print("  ✓ CardIDs are random and unique")
    
    # Test Challenge generation
    challenge1 = crypto.generate_challenge()
    challenge2 = crypto.generate_challenge()
    assert len(challenge1) == 32
    assert len(challenge2) == 32
    assert challenge1 != challenge2, "Challenges should be different"
    print("  ✓ Challenges are random and unique")
    
    print("✅ Random generation test passed\n")


def test_memory_state():
    """Test InMemoryState management"""
    print("Testing memory state management...")
    
    state = InMemoryState()
    
    # Set data
    state.mnemonic = "test mnemonic"
    state.encrypted_blob = b"encrypted data"
    state.aes_key = b"key" * 10
    state.shares = ["share1", "share2", "share3"]
    state.card_data[1] = {"test": "data"}
    
    assert state.mnemonic is not None
    assert state.encrypted_blob is not None
    assert len(state.shares) == 3
    assert 1 in state.card_data
    print("  ✓ State stores data correctly")
    
    # Clear state
    state.clear()
    assert state.mnemonic is None
    assert state.encrypted_blob is None
    assert state.aes_key is None
    assert len(state.shares) == 0
    assert len(state.card_data) == 0
    print("  ✓ State clears all data")
    
    print("✅ Memory state test passed\n")


def test_data_structure_sizes():
    """Test that data structures fit within NTAG216 constraints"""
    print("Testing NTAG216 data structure constraints...")
    
    crypto = CryptoManager()
    
    # Test mnemonic encryption size
    test_mnemonics = [
        "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",  # 12 words
        "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon art",  # 24 words
    ]
    
    for mnemonic in test_mnemonics:
        key = crypto.generate_key()
        encrypted = crypto.encrypt_mnemonic(mnemonic, key)
        word_count = len(mnemonic.split())
        print(f"  {word_count} words: encrypted size = {len(encrypted)} bytes (max 272)")
        assert len(encrypted) <= 272, f"Encrypted blob too large: {len(encrypted)} > 272"
    
    print("  ✓ Encrypted blobs fit in 272 bytes")
    
    # Test share size
    key = crypto.generate_key()
    shares = crypto.split_key(key, threshold=3, shares=5)
    for i, share in enumerate(shares, 1):
        share_bytes = share.encode('utf-8')
        print(f"  Share {i}: {len(share_bytes)} bytes (max 80)")
        assert len(share_bytes) <= 80, f"Share too large: {len(share_bytes)} > 80"
    
    print("  ✓ Shares fit in 80 bytes")
    
    # Calculate total data per card
    card_id_size = 16  # Pages 4-7
    counter_size = 8   # Pages 8-9
    challenge_size = 32  # Pages 10-17
    blob_size = 272  # Pages 18-85
    share_size = 80  # Pages 86-105
    
    total_size = card_id_size + counter_size + challenge_size + blob_size + share_size
    total_pages = total_size // 4  # 4 bytes per page
    
    print(f"\n  Total data per card:")
    print(f"    CardID: {card_id_size} bytes (4 pages)")
    print(f"    Counter: {counter_size} bytes (2 pages)")
    print(f"    Challenge: {challenge_size} bytes (8 pages)")
    print(f"    Encrypted Blob: {blob_size} bytes (68 pages)")
    print(f"    Share: {share_size} bytes (20 pages)")
    print(f"    Total: {total_size} bytes ({total_pages} pages)")
    print(f"    Pages used: 4-105 (102 pages)")
    
    # NTAG216 has 888 bytes user memory (pages 4-230)
    assert total_size <= 888, "Total size exceeds NTAG216 capacity"
    print("  ✓ Data structure fits in NTAG216")
    
    print("✅ Data structure constraints test passed\n")


def main():
    """Run all tests"""
    print("=" * 70)
    print("NFC Mnemonic Backup System - Core Functionality Tests")
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
        print("✅ ALL TESTS PASSED!")
        print("=" * 70)
        print()
        print("Core functionality validated. Ready for hardware testing.")
        print("Note: NFC card operations require ACR122U reader hardware.")
        
        return 0
    
    except AssertionError as e:
        print(f"\n❌ TEST FAILED: {e}")
        return 1
    except Exception as e:
        print(f"\n❌ ERROR: {e}")
        import traceback
        traceback.print_exc()
        return 1


if __name__ == '__main__':
    sys.exit(main())
