#!/usr/bin/env python3
"""
NFC 助记词备份系统 - 后端服务器

本系统提供：
- 助记词的 AES 加密
- Shamir 秘密共享（3-of-5）密钥分片
- 使用 ACR122U 读卡器读写 NFC 卡（NTAG216）
- 前端通信的 WebSocket 服务器（仅 127.0.0.1）
- 仅内存存储（不持久化到磁盘）
- 使用内部数据（CardID + Counter + Challenge）识别卡片
"""

import asyncio
import json
import struct
from typing import Optional, Dict, List, Tuple
from aiohttp import web
import aiohttp
import random

from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes

from smartcard.System import readers
from smartcard.util import toHexString, toBytes
from smartcard.Exceptions import NoCardException, CardConnectionException


class ShamirSecretSharing:
    """简单的 Shamir 秘密共享实现"""
    
    # 用于有限域算术的大素数（256位素数）
    PRIME = 2**256 - 189
    
    @staticmethod
    def _eval_at(poly: List[int], x: int, prime: int) -> int:
        """使用 Horner 方法在 x 处计算多项式"""
        accum = 0
        for coeff in reversed(poly):
            accum = (accum * x + coeff) % prime
        return accum
    
    @staticmethod
    def _lagrange_interpolate(x: int, x_s: List[int], y_s: List[int], prime: int) -> int:
        """在 x 处进行拉格朗日插值"""
        k = len(x_s)
        result = 0
        
        for i in range(k):
            numerator = 1
            denominator = 1
            
            for j in range(k):
                if i != j:
                    numerator = (numerator * (x - x_s[j])) % prime
                    denominator = (denominator * (x_s[i] - x_s[j])) % prime
            
            # 计算分母的模逆
            denominator_inv = pow(denominator, prime - 2, prime)
            
            # 将此项添加到结果
            lagrange_coeff = (numerator * denominator_inv) % prime
            result = (result + y_s[i] * lagrange_coeff) % prime
        
        return result
    
    @classmethod
    def split_secret(cls, secret: bytes, threshold: int, num_shares: int) -> List[str]:
        """将秘密分片"""
        if threshold > num_shares:
            raise ValueError("阈值不能大于分片数量")
        if threshold < 2:
            raise ValueError("阈值必须至少为 2")
        
        # 将秘密转换为整数
        secret_int = int.from_bytes(secret, byteorder='big')
        
        if secret_int >= cls.PRIME:
            raise ValueError("秘密太大")
        
        # 生成随机多项式系数
        # 多项式: a0 + a1*x + a2*x^2 + ... + a(t-1)*x^(t-1)
        # 其中 a0 = secret
        poly = [secret_int]
        for _ in range(threshold - 1):
            coeff = random.SystemRandom().randrange(1, cls.PRIME)
            poly.append(coeff)
        
        # 通过在 x = 1, 2, 3, ..., num_shares 处计算多项式来生成分片
        shares = []
        for x in range(1, num_shares + 1):
            y = cls._eval_at(poly, x, cls.PRIME)
            # 格式: x:y (都是十六进制)
            share_str = f"{x:02x}:{y:064x}"
            shares.append(share_str)
        
        return shares
    
    @classmethod
    def recover_secret(cls, shares: List[str]) -> bytes:
        """从分片中恢复秘密"""
        if len(shares) < 2:
            raise ValueError("至少需要 2 个分片")
        
        # 解析分片
        x_s = []
        y_s = []
        
        for share in shares:
            parts = share.split(':')
            if len(parts) != 2:
                raise ValueError("无效的分片格式")
            
            x = int(parts[0], 16)
            y = int(parts[1], 16)
            
            x_s.append(x)
            y_s.append(y)
        
        # 使用拉格朗日插值在 x=0 处恢复秘密
        secret_int = cls._lagrange_interpolate(0, x_s, y_s, cls.PRIME)
        
        # 转换回字节（32 字节 = 256 位）
        secret = secret_int.to_bytes(32, byteorder='big')
        
        return secret


class InMemoryState:
    """仅内存状态存储 - 重启或断开连接时清除"""
    
    def __init__(self):
        self.mnemonic: Optional[str] = None
        self.encrypted_blob: Optional[bytes] = None
        self.aes_key: Optional[bytes] = None
        self.shares: List[str] = []
        self.card_data: Dict[int, Dict] = {}  # card_number -> {cardid, counter, challenge, share}
        self.recovered_shares: List[str] = []
        self.recovered_mnemonic: Optional[str] = None
    
    def clear(self):
        """从内存中清除所有敏感数据"""
        self.mnemonic = None
        self.encrypted_blob = None
        self.aes_key = None
        self.shares.clear()
        self.card_data.clear()
        self.recovered_shares.clear()
        self.recovered_mnemonic = None


class NFCCardManager:
    """使用 ACR122U 读卡器管理 NFC 卡操作"""
    
    # NTAG216 规格
    NTAG216_PAGES = 231  # 总用户页数（4-230）
    NTAG216_PAGE_SIZE = 4  # 每页字节数
    USER_START_PAGE = 4  # 用户内存起始页
    
    # 卡上的数据结构（从第 4 页开始）：
    # 第 4-7 页：CardID（16 字节）
    # 第 8-9 页：Counter（8 字节）
    # 第 10-17 页：Challenge（32 字节）
    # 第 18-85 页：加密数据块（最大 272 字节 - 足够存储 24 词助记词）
    # 第 86-105 页：分片数据（最大 80 字节）
    
    def __init__(self):
        self.connection = None
        self.current_card_signature: Optional[Dict] = None
    
    def connect(self) -> bool:
        """连接到 ACR122U 读卡器和卡片"""
        try:
            reader_list = readers()
            if not reader_list:
                return False
            
            reader = reader_list[0]
            self.connection = reader.createConnection()
            self.connection.connect()
            return True
        except Exception:
            return False
    
    def disconnect(self):
        """断开与卡片的连接"""
        if self.connection:
            try:
                self.connection.disconnect()
            except Exception:
                pass
            self.connection = None
        self.current_card_signature = None
    
    def read_page(self, page: int) -> Optional[bytes]:
        """从 NTAG216 读取单个页（4 字节）"""
        if not self.connection:
            return None
        
        try:
            # APDU 命令从指定页开始读取 16 字节（4 页）
            apdu = [0xFF, 0xB0, 0x00, page, 0x10]
            data, sw1, sw2 = self.connection.transmit(apdu)
            
            if sw1 == 0x90 and sw2 == 0x00:
                return bytes(data[:4])  # 仅返回第一页
            return None
        except Exception:
            return None
    
    def write_page(self, page: int, data: bytes) -> bool:
        """向 NTAG216 写入单个页（4 字节）"""
        if not self.connection or len(data) != 4:
            return False
        
        try:
            # APDU 命令向页写入 4 字节
            apdu = [0xFF, 0xD6, 0x00, page, 0x04] + list(data)
            data_resp, sw1, sw2 = self.connection.transmit(apdu)
            return sw1 == 0x90 and sw2 == 0x00
        except Exception:
            return False
    
    def read_multiple_pages(self, start_page: int, num_pages: int) -> Optional[bytes]:
        """从卡片读取多个页"""
        result = bytearray()
        for i in range(num_pages):
            page_data = self.read_page(start_page + i)
            if page_data is None:
                return None
            result.extend(page_data)
        return bytes(result)
    
    def write_multiple_pages(self, start_page: int, data: bytes) -> bool:
        """向卡片写入多个页"""
        num_pages = (len(data) + 3) // 4  # 向上取整
        padded_data = data + b'\x00' * (num_pages * 4 - len(data))
        
        for i in range(num_pages):
            page_data = padded_data[i*4:(i+1)*4]
            if not self.write_page(start_page + i, page_data):
                return False
        return True
    
    def read_card_signature(self) -> Optional[Dict]:
        """读取卡片识别数据（CardID + Counter + Challenge）"""
        if not self.connection:
            return None
        
        try:
            # 读取 CardID（16 字节，第 4-7 页）
            card_id = self.read_multiple_pages(4, 4)
            if not card_id:
                return None
            
            # 读取 Counter（8 字节，第 8-9 页）
            counter = self.read_multiple_pages(8, 2)
            if not counter:
                return None
            
            # 读取 Challenge（32 字节，第 10-17 页）
            challenge = self.read_multiple_pages(10, 8)
            if not challenge:
                return None
            
            return {
                'card_id': card_id.hex(),
                'counter': struct.unpack('>Q', counter)[0],
                'challenge': challenge.hex()
            }
        except Exception:
            return None
    
    def is_card_changed(self) -> Tuple[bool, Optional[Dict]]:
        """通过比较签名检查卡片是否已更换"""
        new_signature = self.read_card_signature()
        
        if new_signature is None:
            return True, None
        
        if self.current_card_signature is None:
            # 第一次读卡
            self.current_card_signature = new_signature
            return False, new_signature
        
        # 比较签名
        changed = (new_signature['card_id'] != self.current_card_signature['card_id'] or
                  new_signature['counter'] != self.current_card_signature['counter'] or
                  new_signature['challenge'] != self.current_card_signature['challenge'])
        
        if changed:
            self.current_card_signature = new_signature
            return True, new_signature
        
        return False, new_signature
    
    def write_card_data(self, card_number: int, encrypted_blob: bytes, 
                       share: str, card_id: bytes, challenge: bytes) -> bool:
        """将所有数据写入 NFC 卡"""
        if not self.connection:
            return False
        
        try:
            # 生成计数器（当前时间戳）
            counter = struct.pack('>Q', int(asyncio.get_event_loop().time() * 1000))
            
            # 写入 CardID（第 4-7 页）
            if not self.write_multiple_pages(4, card_id[:16]):
                return False
            
            # 写入 Counter（第 8-9 页）
            if not self.write_multiple_pages(8, counter):
                return False
            
            # 写入 Challenge（第 10-17 页）
            if not self.write_multiple_pages(10, challenge[:32]):
                return False
            
            # 写入加密数据块（第 18-85 页，最大 272 字节）
            blob_to_write = encrypted_blob[:272]
            if not self.write_multiple_pages(18, blob_to_write):
                return False
            
            # 写入分片（第 86-105 页，最大 80 字节）
            share_bytes = share.encode('utf-8')[:80]
            if not self.write_multiple_pages(86, share_bytes):
                return False
            
            return True
        except Exception:
            return False
    
    def read_card_data(self) -> Optional[Dict]:
        """从 NFC 卡读取所有数据"""
        if not self.connection:
            return None
        
        try:
            # 首先读取签名
            signature = self.read_card_signature()
            if not signature:
                return None
            
            # 读取加密数据块（第 18-85 页）
            encrypted_blob = self.read_multiple_pages(18, 68)  # 272 字节
            if not encrypted_blob:
                return None
            
            # 读取分片（第 86-105 页）
            share_data = self.read_multiple_pages(86, 20)  # 80 字节
            if not share_data:
                return None
            
            # 解码分片
            share = share_data.rstrip(b'\x00').decode('utf-8', errors='ignore')
            
            return {
                'signature': signature,
                'encrypted_blob': encrypted_blob.rstrip(b'\x00'),
                'share': share
            }
        except Exception:
            return None


class CryptoManager:
    """处理加密和秘密共享操作"""
    
    @staticmethod
    def encrypt_mnemonic(mnemonic: str, key: bytes) -> bytes:
        """使用 AES-256-GCM 加密助记词"""
        # 生成随机 nonce
        nonce = get_random_bytes(12)
        
        # 创建加密器
        cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
        
        # 加密
        ciphertext, tag = cipher.encrypt_and_digest(mnemonic.encode('utf-8'))
        
        # 返回：nonce (12) + tag (16) + 密文
        return nonce + tag + ciphertext
    
    @staticmethod
    def decrypt_mnemonic(encrypted_blob: bytes, key: bytes) -> Optional[str]:
        """使用 AES-256-GCM 解密助记词"""
        try:
            # 提取组件
            nonce = encrypted_blob[:12]
            tag = encrypted_blob[12:28]
            ciphertext = encrypted_blob[28:]
            
            # 创建加密器
            cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
            
            # 解密和验证
            plaintext = cipher.decrypt_and_verify(ciphertext, tag)
            
            return plaintext.decode('utf-8')
        except Exception:
            return None
    
    @staticmethod
    def split_key(key: bytes, threshold: int = 3, shares: int = 5) -> List[str]:
        """使用 Shamir 秘密共享分片密钥"""
        return ShamirSecretSharing.split_secret(key, threshold, shares)
    
    @staticmethod
    def recover_key(shares: List[str]) -> Optional[bytes]:
        """从分片恢复密钥"""
        try:
            return ShamirSecretSharing.recover_secret(shares)
        except Exception:
            return None
    
    @staticmethod
    def generate_key() -> bytes:
        """生成一个随机的 256 位 AES 密钥"""
        return get_random_bytes(32)
    
    @staticmethod
    def generate_card_id() -> bytes:
        """生成一个随机的卡片 ID"""
        return get_random_bytes(16)
    
    @staticmethod
    def generate_challenge() -> bytes:
        """生成一个随机的挑战值"""
        return get_random_bytes(32)


class WebSocketHandler:
    """处理 WebSocket 连接和消息"""
    
    def __init__(self):
        self.state = InMemoryState()
        self.nfc = NFCCardManager()
        self.crypto = CryptoManager()
        self.ws_connections = set()
    
    async def handle_websocket(self, request):
        """处理 WebSocket 连接"""
        ws = web.WebSocketResponse()
        await ws.prepare(request)
        
        self.ws_connections.add(ws)
        
        try:
            async for msg in ws:
                if msg.type == aiohttp.WSMsgType.TEXT:
                    await self.handle_message(ws, msg.data)
                elif msg.type == aiohttp.WSMsgType.ERROR:
                    print(f'WebSocket error: {ws.exception()}')
        finally:
            self.ws_connections.discard(ws)
            # 连接关闭时清除状态
            self.state.clear()
        
        return ws
    
    async def handle_message(self, ws, data: str):
        """处理传入的 WebSocket 消息"""
        try:
            message = json.loads(data)
            action = message.get('action')
            
            if action == 'backup_start':
                await self.handle_backup_start(ws, message)
            elif action == 'backup_write_card':
                await self.handle_backup_write_card(ws, message)
            elif action == 'recovery_start':
                await self.handle_recovery_start(ws, message)
            elif action == 'recovery_read_card':
                await self.handle_recovery_read_card(ws, message)
            elif action == 'check_reader':
                await self.handle_check_reader(ws, message)
            else:
                await self.send_error(ws, f"Unknown action: {action}")
        
        except json.JSONDecodeError:
            await self.send_error(ws, "Invalid JSON")
        except Exception as e:
            await self.send_error(ws, f"Error: {str(e)}")
    
    async def handle_backup_start(self, ws, message):
        """初始化备份过程"""
        mnemonic = message.get('mnemonic', '').strip()
        
        if not mnemonic:
            await self.send_error(ws, "Mnemonic is required")
            return
        
        # 生成 AES 密钥
        aes_key = self.crypto.generate_key()
        
        # 加密助记词
        encrypted_blob = self.crypto.encrypt_mnemonic(mnemonic, aes_key)
        
        # 将密钥分片（3-of-5）
        shares = self.crypto.split_key(aes_key, threshold=3, shares=5)
        
        # 存储到内存
        self.state.mnemonic = mnemonic
        self.state.encrypted_blob = encrypted_blob
        self.state.aes_key = aes_key
        self.state.shares = shares
        
        await self.send_response(ws, {
            'action': 'backup_initialized',
            'total_cards': 5,
            'encrypted_blob_size': len(encrypted_blob),
            'shares_count': len(shares)
        })
    
    async def handle_backup_write_card(self, ws, message):
        """将数据写入 NFC 卡"""
        card_number = message.get('card_number', 1)
        
        if not self.state.encrypted_blob or not self.state.shares:
            await self.send_error(ws, "Backup not initialized")
            return
        
        if card_number < 1 or card_number > 5:
            await self.send_error(ws, "Invalid card number (must be 1-5)")
            return
        
        # 连接到读卡器
        if not self.nfc.connect():
            await self.send_error(ws, "Failed to connect to NFC reader")
            return
        
        try:
            # 生成卡片 ID 和挑战值
            card_id = self.crypto.generate_card_id()
            challenge = self.crypto.generate_challenge()
            
            # 获取此卡的分片
            share = self.state.shares[card_number - 1]
            
            # 写入卡片
            success = self.nfc.write_card_data(
                card_number,
                self.state.encrypted_blob,
                share,
                card_id,
                challenge
            )
            
            if success:
                # 存储卡片信息
                self.state.card_data[card_number] = {
                    'card_id': card_id.hex(),
                    'challenge': challenge.hex(),
                    'share': share,
                    'written': True
                }
                
                await self.send_response(ws, {
                    'action': 'card_written',
                    'card_number': card_number,
                    'success': True
                })
            else:
                await self.send_error(ws, f"Failed to write card {card_number}")
        
        finally:
            self.nfc.disconnect()
    
    async def handle_recovery_start(self, ws, message):
        """初始化恢复过程"""
        # 清除之前的恢复数据
        self.state.recovered_shares.clear()
        self.state.recovered_mnemonic = None
        
        await self.send_response(ws, {
            'action': 'recovery_initialized',
            'required_cards': 3
        })
    
    async def handle_recovery_read_card(self, ws, message):
        """从 NFC 卡读取数据进行恢复"""
        # 连接到读卡器
        if not self.nfc.connect():
            await self.send_error(ws, "Failed to connect to NFC reader")
            return
        
        try:
            # 读取卡片数据
            card_data = self.nfc.read_card_data()
            
            if not card_data:
                await self.send_error(ws, "Failed to read card data")
                return
            
            # 检查是否为新卡
            changed, signature = self.nfc.is_card_changed()
            
            if not changed and len(self.state.recovered_shares) > 0:
                await self.send_error(ws, "Same card detected - please insert a different card")
                return
            
            # 如果尚未存储，则存储加密数据块
            if not self.state.encrypted_blob:
                self.state.encrypted_blob = card_data['encrypted_blob']
            
            # 将分片添加到已恢复的分片中
            share = card_data['share']
            if share and share not in self.state.recovered_shares:
                self.state.recovered_shares.append(share)
            
            cards_read = len(self.state.recovered_shares)
            
            # 检查是否有足够的分片
            if cards_read >= 3:
                # 尝试恢复
                recovered_key = self.crypto.recover_key(self.state.recovered_shares[:3])
                
                if recovered_key and self.state.encrypted_blob:
                    recovered_mnemonic = self.crypto.decrypt_mnemonic(
                        self.state.encrypted_blob,
                        recovered_key
                    )
                    
                    if recovered_mnemonic:
                        self.state.recovered_mnemonic = recovered_mnemonic
                        
                        await self.send_response(ws, {
                            'action': 'recovery_complete',
                            'mnemonic': recovered_mnemonic,
                            'cards_used': cards_read
                        })
                        return
                
                await self.send_error(ws, "Failed to recover mnemonic")
            else:
                await self.send_response(ws, {
                    'action': 'card_read',
                    'cards_read': cards_read,
                    'required': 3
                })
        
        finally:
            self.nfc.disconnect()
    
    async def handle_check_reader(self, ws, message):
        """检查 NFC 读卡器是否可用"""
        connected = self.nfc.connect()
        if connected:
            self.nfc.disconnect()
        
        await self.send_response(ws, {
            'action': 'reader_status',
            'available': connected
        })
    
    async def send_response(self, ws, data: dict):
        """向 WebSocket 客户端发送响应"""
        await ws.send_json(data)
    
    async def send_error(self, ws, error: str):
        """向 WebSocket 客户端发送错误"""
        await ws.send_json({
            'action': 'error',
            'error': error
        })


async def create_app():
    """创建和配置 Web 应用"""
    app = web.Application()
    
    handler = WebSocketHandler()
    
    # WebSocket 端点
    app.router.add_get('/ws', handler.handle_websocket)
    
    # 提供静态文件（前端）
    app.router.add_static('/', path='./static', name='static')
    
    return app


def main():
    """主入口点"""
    app = create_app()
    
    # 仅在 localhost 上运行以确保安全
    web.run_app(app, host='127.0.0.1', port=8080)


if __name__ == '__main__':
    main()
