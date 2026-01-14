import socket
import hashlib
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad

HOST = "0.0.0.0"
PORT = 5000

# ⚠️ Même clé que sur le STM32 (AES-128 = 16 bytes)
AES_KEY = bytes.fromhex("00112233445566778899AABBCCDDEEFF")

def parse_kv_line(line: str) -> dict:
    parts = line.strip().split(";")
    out = {}
    for p in parts:
        if "=" in p:
            k, v = p.split("=", 1)
            out[k.strip().upper()] = v.strip()
    return out

def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()

def decrypt_aes_cbc(iv_hex: str, ct_hex: str) -> bytes:
    iv = bytes.fromhex(iv_hex)
    ct = bytes.fromhex(ct_hex)
    cipher = AES.new(AES_KEY, AES.MODE_CBC, iv=iv)
    pt_padded = cipher.decrypt(ct)
    return unpad(pt_padded, 16)  # PKCS7

def main():
    print(f"[+] TCP server listening on {HOST}:{PORT}")
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind((HOST, PORT))
        s.listen(1)

        conn, addr = s.accept()
        with conn:
            print(f"[+] Client connected: {addr}")
            buf = b""
            while True:
                chunk = conn.recv(4096)
                if not chunk:
                    print("[-] Client disconnected")
                    break
                buf += chunk

                while b"\n" in buf:
                    line, buf = buf.split(b"\n", 1)
                    text = line.decode("utf-8", errors="replace")

                    try:
                        kv = parse_kv_line(text)
                        nonce = kv.get("NONCE", "?")
                        iv_hex = kv["IV"]
                        ct_hex = kv["CT"]
                        tag_hex = kv["TAG"].lower()

                        pt = decrypt_aes_cbc(iv_hex, ct_hex)
                        calc = sha256_hex(pt)

                        if calc != tag_hex:
                            print(f"[!] NONCE={nonce} INTEGRITY FAIL (tag mismatch)")
                            continue

                        payload = pt.decode("utf-8", errors="replace").strip()
                        print(f"[OK] NONCE={nonce} {payload}")

                    except Exception as e:
                        print(f"[!] Error parsing/decrypting line: {e}")
                        print(f"    Raw: {text}")

if __name__ == "__main__":
    main()
