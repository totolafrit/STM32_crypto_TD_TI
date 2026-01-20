import asyncio
import serial
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
 
# --- CONFIGURATION (À copier depuis ta STM32) ---
AES_KEY_HEX = "85883C924BFAA81881CB75086CBBAFC5179E789B1CCABD21FEC6ACC3C28F7EB3" .strip().replace(" ", "")
AES_KEY = bytes.fromhex(AES_KEY_HEX)
 
PUBLIC_KEY_DER_HEX = "3059301306072A8648CE3D020106082A8648CE3D0301070342000454DCF70EF30F9126FBC0F7BA20A91FBD734A18E4A5556A9CFC63206839C3E7835BAEA229D58B2D770B6ECE7260E8292626DDD988541FC8760C95D82B16166E8A".strip().replace(" ", "")
PUBLIC_KEY_DER = bytes.fromhex(PUBLIC_KEY_DER_HEX)
 
public_key = serialization.load_der_public_key(PUBLIC_KEY_DER)
 
IV_FIXE = b'\x10' * 16
 
# État partagé pour l'interface web (doit correspondre à la structure de web_server)
STATE = {"temp": None, "pressure": None, "counter": 0, "status": "idle"}
 
async def run_serial_gateway(broadcast_func):
    public_key = serialization.load_der_public_key(PUBLIC_KEY_DER)
    ser = serial.Serial('COM4', 115200, timeout=0.1)
   
    while True:
        if ser.in_waiting >= 23:
            if ser.read(1) == b'\xaa': # Header 0xAA
                try:
                    counter = int.from_bytes(ser.read(4), 'little')
                    ciphertext = ser.read(16)
                    sig_len = int.from_bytes(ser.read(1), 'little')
                    signature = ser.read(sig_len)
 
                    # 1. Vérification Signature ECDSA
                    public_key.verify(signature, ciphertext, ec.ECDSA(hashes.SHA256()))
                   
                    # 2. Déchiffrement AES-256-CBC
                    cipher = Cipher(algorithms.AES(AES_KEY), modes.CBC(IV_FIXE))
                    decryptor = cipher.decryptor()
                    plain = decryptor.update(ciphertext) + decryptor.finalize()
 
                    # 3. Extraction de la Température ET de la Pression
                    # Température (int16 aux octets 4-5)
                    temp_raw = int.from_bytes(plain[4:6], 'little', signed=True)
                    STATE["temp"] = round((temp_raw / 100.0) - 6.0, 2)
 
                    # Pression (uint24 aux octets 6-8)
                    press_raw = int.from_bytes(plain[6:9], 'little')
                    STATE["pressure"] = round(press_raw / 4096.0, 2)
                   
                    STATE["counter"] = counter
 
                    # 4. Envoi vers le site web
                    await broadcast_func({"type": "data", **STATE})
                   
                except Exception as e:
                    # Affiche l'erreur réelle pour le debug
                    print(f"Erreur Sécurité détaillée : {type(e).__name__} - {e}")
        await asyncio.sleep(0.01)
 