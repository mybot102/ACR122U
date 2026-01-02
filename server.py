#!/usr/bin/env python3
"""
NFC Mnemonic Backup System - Backend Server

This system provides:
- AES encryption of mnemonic phrases
- Shamir Secret Sharing (3-of-5) for key splitting
- NFC card (NTAG216) read/write using ACR122U reader
- WebSocket server for frontend communication (127.0.0.1 only)
- Memory-only storage (no disk persistence)
- Card identification using internal data (CardID + Counter + Challenge)
"""

import asyncio
import json
import secrets
import struct
import hashlib
from typing import Optional, Dict, List, Tuple
from aiohttp import web
import aiohttp

from Crypto.Cipher import AES
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Random import get_random_bytes
from secretsharing import SecretSharer

from smartcard.System import readers
from smartcard.util import toHexString, toBytes
from smartcard.Exceptions import NoCardException, CardConnectionException


class InMemoryState:
    """Memory-only state storage - cleared on restart or disconnect"""
    
    def __init__(self):
        self.mnemonic: Optional[str] = None
        self.encrypted_blob: Optional[bytes] = None
        self.aes_key: Optional[bytes] = None
        self.shares: List[str] = []
        self.card_data: Dict[int, Dict] = {}  # card_number -> {cardid, counter, challenge, share}
        self.recovered_shares: List[str] = []
        self.recovered_mnemonic: Optional[str] = None
    
    def clear(self):
        """Clear all sensitive data from memory"""
        self.mnemonic = None
        self.encrypted_blob = None
        self.aes_key = None
        self.shares.clear()
        self.card_data.clear()
        self.recovered_shares.clear()
        self.recovered_mnemonic = None


class NFCCardManager:
    """Manages NFC card operations using ACR122U reader"""
    
    # NTAG216 specifications
    NTAG216_PAGES = 231  # Total user pages (4-230)
    NTAG216_PAGE_SIZE = 4  # bytes per page
    USER_START_PAGE = 4  # Start of user memory
    
    # Our data structure on card (starting at page 4):
    # Pages 4-7: CardID (16 bytes)
    # Pages 8-9: Counter (8 bytes)
    # Pages 10-17: Challenge (32 bytes)
    # Pages 18-49: Encrypted Blob (128 bytes max)
    # Pages 50-65: Share data (64 bytes max)
    
    def __init__(self):
        self.connection = None
        self.current_card_signature: Optional[Dict] = None
    
    def connect(self) -> bool:
        """Connect to ACR122U reader and card"""
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
        """Disconnect from card"""
        if self.connection:
            try:
                self.connection.disconnect()
            except Exception:
                pass
            self.connection = None
        self.current_card_signature = None
    
    def read_page(self, page: int) -> Optional[bytes]:
        """Read a single page (4 bytes) from NTAG216"""
        if not self.connection:
            return None
        
        try:
            # APDU command to read 16 bytes (4 pages) starting at page
            apdu = [0xFF, 0xB0, 0x00, page, 0x10]
            data, sw1, sw2 = self.connection.transmit(apdu)
            
            if sw1 == 0x90 and sw2 == 0x00:
                return bytes(data[:4])  # Return only first page
            return None
        except Exception:
            return None
    
    def write_page(self, page: int, data: bytes) -> bool:
        """Write a single page (4 bytes) to NTAG216"""
        if not self.connection or len(data) != 4:
            return False
        
        try:
            # APDU command to write 4 bytes to page
            apdu = [0xFF, 0xD6, 0x00, page, 0x04] + list(data)
            data_resp, sw1, sw2 = self.connection.transmit(apdu)
            return sw1 == 0x90 and sw2 == 0x00
        except Exception:
            return False
    
    def read_multiple_pages(self, start_page: int, num_pages: int) -> Optional[bytes]:
        """Read multiple pages from card"""
        result = bytearray()
        for i in range(num_pages):
            page_data = self.read_page(start_page + i)
            if page_data is None:
                return None
            result.extend(page_data)
        return bytes(result)
    
    def write_multiple_pages(self, start_page: int, data: bytes) -> bool:
        """Write multiple pages to card"""
        num_pages = (len(data) + 3) // 4  # Round up
        padded_data = data + b'\x00' * (num_pages * 4 - len(data))
        
        for i in range(num_pages):
            page_data = padded_data[i*4:(i+1)*4]
            if not self.write_page(start_page + i, page_data):
                return False
        return True
    
    def read_card_signature(self) -> Optional[Dict]:
        """Read card identification data (CardID + Counter + Challenge)"""
        if not self.connection:
            return None
        
        try:
            # Read CardID (16 bytes, pages 4-7)
            card_id = self.read_multiple_pages(4, 4)
            if not card_id:
                return None
            
            # Read Counter (8 bytes, pages 8-9)
            counter = self.read_multiple_pages(8, 2)
            if not counter:
                return None
            
            # Read Challenge (32 bytes, pages 10-17)
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
        """Check if card has been changed by comparing signatures"""
        new_signature = self.read_card_signature()
        
        if new_signature is None:
            return True, None
        
        if self.current_card_signature is None:
            # First card read
            self.current_card_signature = new_signature
            return False, new_signature
        
        # Compare signatures
        changed = (new_signature['card_id'] != self.current_card_signature['card_id'] or
                  new_signature['counter'] != self.current_card_signature['counter'] or
                  new_signature['challenge'] != self.current_card_signature['challenge'])
        
        if changed:
            self.current_card_signature = new_signature
            return True, new_signature
        
        return False, new_signature
    
    def write_card_data(self, card_number: int, encrypted_blob: bytes, 
                       share: str, card_id: bytes, challenge: bytes) -> bool:
        """Write all data to NFC card"""
        if not self.connection:
            return False
        
        try:
            # Generate counter (current timestamp)
            counter = struct.pack('>Q', int(asyncio.get_event_loop().time() * 1000))
            
            # Write CardID (pages 4-7)
            if not self.write_multiple_pages(4, card_id[:16]):
                return False
            
            # Write Counter (pages 8-9)
            if not self.write_multiple_pages(8, counter):
                return False
            
            # Write Challenge (pages 10-17)
            if not self.write_multiple_pages(10, challenge[:32]):
                return False
            
            # Write Encrypted Blob (pages 18-49, max 128 bytes)
            blob_to_write = encrypted_blob[:128]
            if not self.write_multiple_pages(18, blob_to_write):
                return False
            
            # Write Share (pages 50-65, max 64 bytes)
            share_bytes = share.encode('utf-8')[:64]
            if not self.write_multiple_pages(50, share_bytes):
                return False
            
            return True
        except Exception:
            return False
    
    def read_card_data(self) -> Optional[Dict]:
        """Read all data from NFC card"""
        if not self.connection:
            return None
        
        try:
            # Read signature first
            signature = self.read_card_signature()
            if not signature:
                return None
            
            # Read Encrypted Blob (pages 18-49)
            encrypted_blob = self.read_multiple_pages(18, 32)  # 128 bytes
            if not encrypted_blob:
                return None
            
            # Read Share (pages 50-65)
            share_data = self.read_multiple_pages(50, 16)  # 64 bytes
            if not share_data:
                return None
            
            # Decode share
            share = share_data.rstrip(b'\x00').decode('utf-8', errors='ignore')
            
            return {
                'signature': signature,
                'encrypted_blob': encrypted_blob.rstrip(b'\x00'),
                'share': share
            }
        except Exception:
            return None


class CryptoManager:
    """Handles encryption and secret sharing operations"""
    
    @staticmethod
    def encrypt_mnemonic(mnemonic: str, key: bytes) -> bytes:
        """Encrypt mnemonic using AES-256-GCM"""
        # Generate random nonce
        nonce = get_random_bytes(12)
        
        # Create cipher
        cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
        
        # Encrypt
        ciphertext, tag = cipher.encrypt_and_digest(mnemonic.encode('utf-8'))
        
        # Return: nonce (12) + tag (16) + ciphertext
        return nonce + tag + ciphertext
    
    @staticmethod
    def decrypt_mnemonic(encrypted_blob: bytes, key: bytes) -> Optional[str]:
        """Decrypt mnemonic using AES-256-GCM"""
        try:
            # Extract components
            nonce = encrypted_blob[:12]
            tag = encrypted_blob[12:28]
            ciphertext = encrypted_blob[28:]
            
            # Create cipher
            cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
            
            # Decrypt and verify
            plaintext = cipher.decrypt_and_verify(ciphertext, tag)
            
            return plaintext.decode('utf-8')
        except Exception:
            return None
    
    @staticmethod
    def split_key(key: bytes, threshold: int = 3, shares: int = 5) -> List[str]:
        """Split key using Shamir Secret Sharing"""
        # Convert key to hex string for secretsharing
        key_hex = key.hex()
        
        # Create shares
        shares_list = SecretSharer.split_secret(key_hex, threshold, shares)
        
        return shares_list
    
    @staticmethod
    def recover_key(shares: List[str]) -> Optional[bytes]:
        """Recover key from shares"""
        try:
            # Recover hex string
            key_hex = SecretSharer.recover_secret(shares)
            
            # Convert back to bytes
            return bytes.fromhex(key_hex)
        except Exception:
            return None
    
    @staticmethod
    def generate_key() -> bytes:
        """Generate a random 256-bit AES key"""
        return get_random_bytes(32)
    
    @staticmethod
    def generate_card_id() -> bytes:
        """Generate a random card ID"""
        return get_random_bytes(16)
    
    @staticmethod
    def generate_challenge() -> bytes:
        """Generate a random challenge"""
        return get_random_bytes(32)


class WebSocketHandler:
    """Handles WebSocket connections and messages"""
    
    def __init__(self):
        self.state = InMemoryState()
        self.nfc = NFCCardManager()
        self.crypto = CryptoManager()
        self.ws_connections = set()
    
    async def handle_websocket(self, request):
        """Handle WebSocket connection"""
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
            # Clear state when connection closes
            self.state.clear()
        
        return ws
    
    async def handle_message(self, ws, data: str):
        """Handle incoming WebSocket message"""
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
        """Initialize backup process"""
        mnemonic = message.get('mnemonic', '').strip()
        
        if not mnemonic:
            await self.send_error(ws, "Mnemonic is required")
            return
        
        # Generate AES key
        aes_key = self.crypto.generate_key()
        
        # Encrypt mnemonic
        encrypted_blob = self.crypto.encrypt_mnemonic(mnemonic, aes_key)
        
        # Split key into shares (3-of-5)
        shares = self.crypto.split_key(aes_key, threshold=3, shares=5)
        
        # Store in memory
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
        """Write data to NFC card"""
        card_number = message.get('card_number', 1)
        
        if not self.state.encrypted_blob or not self.state.shares:
            await self.send_error(ws, "Backup not initialized")
            return
        
        if card_number < 1 or card_number > 5:
            await self.send_error(ws, "Invalid card number (must be 1-5)")
            return
        
        # Connect to reader
        if not self.nfc.connect():
            await self.send_error(ws, "Failed to connect to NFC reader")
            return
        
        try:
            # Generate card ID and challenge
            card_id = self.crypto.generate_card_id()
            challenge = self.crypto.generate_challenge()
            
            # Get share for this card
            share = self.state.shares[card_number - 1]
            
            # Write to card
            success = self.nfc.write_card_data(
                card_number,
                self.state.encrypted_blob,
                share,
                card_id,
                challenge
            )
            
            if success:
                # Store card info
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
        """Initialize recovery process"""
        # Clear previous recovery data
        self.state.recovered_shares.clear()
        self.state.recovered_mnemonic = None
        
        await self.send_response(ws, {
            'action': 'recovery_initialized',
            'required_cards': 3
        })
    
    async def handle_recovery_read_card(self, ws, message):
        """Read data from NFC card for recovery"""
        # Connect to reader
        if not self.nfc.connect():
            await self.send_error(ws, "Failed to connect to NFC reader")
            return
        
        try:
            # Read card data
            card_data = self.nfc.read_card_data()
            
            if not card_data:
                await self.send_error(ws, "Failed to read card data")
                return
            
            # Check if this is a new card
            changed, signature = self.nfc.is_card_changed()
            
            if not changed and len(self.state.recovered_shares) > 0:
                await self.send_error(ws, "Same card detected - please insert a different card")
                return
            
            # Store encrypted blob if not yet stored
            if not self.state.encrypted_blob:
                self.state.encrypted_blob = card_data['encrypted_blob']
            
            # Add share to recovered shares
            share = card_data['share']
            if share and share not in self.state.recovered_shares:
                self.state.recovered_shares.append(share)
            
            cards_read = len(self.state.recovered_shares)
            
            # Check if we have enough shares
            if cards_read >= 3:
                # Attempt recovery
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
        """Check if NFC reader is available"""
        connected = self.nfc.connect()
        if connected:
            self.nfc.disconnect()
        
        await self.send_response(ws, {
            'action': 'reader_status',
            'available': connected
        })
    
    async def send_response(self, ws, data: dict):
        """Send response to WebSocket client"""
        await ws.send_json(data)
    
    async def send_error(self, ws, error: str):
        """Send error to WebSocket client"""
        await ws.send_json({
            'action': 'error',
            'error': error
        })


async def create_app():
    """Create and configure web application"""
    app = web.Application()
    
    handler = WebSocketHandler()
    
    # WebSocket endpoint
    app.router.add_get('/ws', handler.handle_websocket)
    
    # Serve static files (frontend)
    app.router.add_static('/', path='./static', name='static')
    
    return app


def main():
    """Main entry point"""
    app = create_app()
    
    # Run on localhost only for security
    web.run_app(app, host='127.0.0.1', port=8080)


if __name__ == '__main__':
    main()
