import time
import hashlib
import serial
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad

PORT = "COM10"
BAUD = 115200
AES_KEY = bytes.fromhex("00112233445566778899AABBCCDDEEFF")

def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()

def encrypt_aes_cbc(iv: bytes, plaintext: bytes) -> bytes:
    cipher = AES.new(AES_KEY, AES.MODE_CBC, iv=iv)
    return cipher.encrypt(pad(plaintext, 16))

def main():
    ser = serial.Serial(PORT, BAUD, timeout=1)
    nonce = 1
    print(f"[+] Fake STM32 sender on {PORT} @ {BAUD}")

    while True:
        # Simule des capteurs qui changent
        temp = 20.0 + (nonce % 10) * 0.3
        lux = 50 + (nonce % 30)

        plaintext = f"T={temp:.2f};L={lux}".encode()
        iv = bytes.fromhex("00112233445566778899aabbccddeeff")

        ct = encrypt_aes_cbc(iv, plaintext)
        tag = sha256_hex(plaintext)

        line = f"NONCE={nonce};IV={iv.hex()};CT={ct.hex()};TAG={tag}\n"
        ser.write(line.encode())
        print("[SEND]", line.strip())

        nonce += 1
        time.sleep(1)

if __name__ == "__main__":
    main()
