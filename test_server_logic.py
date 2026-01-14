import hashlib
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

AES_KEY = bytes.fromhex("00112233445566778899AABBCCDDEEFF")  # même clé que serveur et STM32

def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()

def encrypt_aes_cbc(iv: bytes, plaintext: bytes) -> bytes:
    cipher = AES.new(AES_KEY, AES.MODE_CBC, iv=iv)
    return cipher.encrypt(pad(plaintext, 16))

def decrypt_aes_cbc(iv_hex: str, ct_hex: str) -> bytes:
    iv = bytes.fromhex(iv_hex)
    ct = bytes.fromhex(ct_hex)
    cipher = AES.new(AES_KEY, AES.MODE_CBC, iv=iv)
    pt_padded = cipher.decrypt(ct)
    return unpad(pt_padded, 16)

def parse_kv_line(line: str) -> dict:
    parts = line.strip().split(";")
    out = {}
    for p in parts:
        if "=" in p:
            k, v = p.split("=", 1)
            out[k.strip().upper()] = v.strip()
    return out

def simulate_one_message():
    # Ce que tu veux voir affiché après déchiffrement (comme capteurs)
    plaintext = b"T=23.60;L=120"
    iv = bytes.fromhex("00112233445566778899AABBCCDDEEFF")

    ct = encrypt_aes_cbc(iv, plaintext)
    tag = sha256_hex(plaintext)

    # La ligne que le STM32 devra envoyer sur COM3 (format TP)
    line = f"NONCE=1;IV={iv.hex()};CT={ct.hex()};TAG={tag}\n"
    print("[SIMULATED LINE SENT BY STM32]")
    print(line)

    # === Côté serveur (réception) ===
    kv = parse_kv_line(line)
    pt = decrypt_aes_cbc(kv["IV"], kv["CT"])
    calc = sha256_hex(pt)

    if calc != kv["TAG"].lower():
        print("[!] INTEGRITY FAIL")
        return

    print("[OK] Decrypted payload =", pt.decode())

if __name__ == "__main__":
    simulate_one_message()
