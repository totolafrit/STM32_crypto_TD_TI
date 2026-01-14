import hashlib
import serial
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad, pad
import time
import re

# =========================
# CONFIGURATION
# =========================
PORT = "COM3"          # Port série (carte STM32)
BAUD = 115200          # Baudrate STM32
AES_KEY = bytes.fromhex("00112233445566778899AABBCCDDEEFF")  # AES-128 (16 bytes)

# Filtre optionnel si STM32 envoie des logs (ex: PREFIX = "NONCE=")
PREFIX = ""

# Mode simulation : True = simule un message STM32 localement (sans COM)
SIMULATE = True


# =========================
# OUTILS
# =========================
def parse_kv_line(line: str) -> dict:
    """
    Parse une ligne du type :
    NONCE=1;IV=...;CT=...;TAG=...
    Tolère espaces et champs en plus.
    """
    out = {}
    for part in line.strip().split(";"):
        part = part.strip()
        if not part:
            continue
        if "=" not in part:
            continue
        k, v = part.split("=", 1)
        out[k.strip().upper()] = v.strip()
    return out


def is_hex(s: str) -> bool:
    return bool(re.fullmatch(r"[0-9a-fA-F]+", s or ""))


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def decrypt_aes_cbc(iv_hex: str, ct_hex: str) -> bytes:
    """
    Déchiffre AES-CBC + PKCS7.
    Lève une exception si IV/CT invalides ou padding KO.
    """
    if not is_hex(iv_hex) or len(iv_hex) != 32:
        raise ValueError(f"IV invalide: attendu 32 hex (16 bytes), reçu len={len(iv_hex)}")

    if not is_hex(ct_hex) or (len(ct_hex) % 32) != 0:
        # 32 hex = 16 bytes, CBC -> multiple de 16 bytes
        raise ValueError(f"CT invalide: doit être hex et multiple de 32 hex (16 bytes). len={len(ct_hex)}")

    iv = bytes.fromhex(iv_hex)
    ct = bytes.fromhex(ct_hex)

    cipher = AES.new(AES_KEY, AES.MODE_CBC, iv=iv)
    pt_padded = cipher.decrypt(ct)

    # PKCS7
    return unpad(pt_padded, 16)


def safe_strip_line(b: bytes) -> str:
    """Decode robuste + enlève \r \n"""
    return b.decode("utf-8", errors="replace").strip().replace("\r", "")


def simulate_line(nonce: int = 1) -> str:
    """
    Génère une fausse trame STM32 valide (AES-CBC + PKCS7 + TAG=SHA256(plaintext))
    Format attendu par le serveur.
    """
    plaintext = b"T=23.60;L=120"
    iv = bytes.fromhex("00112233445566778899AABBCCDDEEFF")

    cipher = AES.new(AES_KEY, AES.MODE_CBC, iv=iv)
    ct = cipher.encrypt(pad(plaintext, 16))

    tag = sha256_hex(plaintext)

    return f"NONCE={nonce};IV={iv.hex()};CT={ct.hex()};TAG={tag}"


def process_line(text: str) -> None:
    """
    Traite une ligne (réelle ou simulée) :
    - parse
    - decrypt
    - check sha256
    - affiche
    - log
    """
    # Ignore lignes vides
    if not text:
        return

    # Filtre optionnel (évite spam si STM32 debug)
    if PREFIX and not text.startswith(PREFIX):
        print(f"[DBG] {text}")
        return

    print(f"[RAW] {text}")

    kv = parse_kv_line(text)

    # Vérif présence champs
    missing = [k for k in ("IV", "CT", "TAG") if k not in kv]
    if missing:
        raise ValueError(f"Champs manquants: {missing} (reçu keys={list(kv.keys())})")

    nonce = kv.get("NONCE", "?")
    iv_hex = kv["IV"]
    ct_hex = kv["CT"]
    tag_hex = kv["TAG"].lower()

    # Vérif TAG
    if (not is_hex(tag_hex)) or len(tag_hex) != 64:
        raise ValueError(f"TAG invalide: attendu 64 hex (sha256). len={len(tag_hex)}")

    # Déchiffrement
    pt = decrypt_aes_cbc(iv_hex, ct_hex)

    # Vérification intégrité
    calc = sha256_hex(pt)
    if calc != tag_hex:
        print(f"[!] NONCE={nonce} -> INTEGRITY FAIL")
        print(f"    TAG recv : {tag_hex}")
        print(f"    TAG calc : {calc}\n")
        return

    payload = pt.decode("utf-8", errors="replace").strip()

    # Affichage démo
    print("================================")
    print(f"NONCE        : {nonce}")
    print(f"TEMP / LUX   : {payload}")
    print("STATUS       : OK (integrity + decrypt)")
    print("================================\n")

    # Log CSV (bonus)
    with open("log.csv", "a", encoding="utf-8") as f:
        f.write(f"{time.time()},{nonce},{payload}\n")


# =========================
# PROGRAMME PRINCIPAL
# =========================
def main():
    print("================================")
    print("  SERVEUR PC - CRYPTO / IOT")
    print("================================")

    if SIMULATE:
        print("[+] SIMULATION MODE: pas besoin de STM32 / COM")
        print("Format attendu : NONCE=...;IV=<32hex>;CT=<hex>;TAG=<64hex>\n")
        try:
            # Simule 5 messages
            for i in range(1, 6):
                text = simulate_line(nonce=i)
                process_line(text)
                time.sleep(1)
        except Exception as e:
            print(f"[!] Parse/crypto error (SIM): {e}")
        return

    # Mode réel : lecture série COM3
    print(f"[+] Listening serial {PORT} @ {BAUD}...")
    print("[+] Waiting for STM32 data...\n")
    print("Format attendu : NONCE=...;IV=<32hex>;CT=<hex>;TAG=<64hex>\\n\n")

    ser = serial.Serial(PORT, BAUD, timeout=1)

    while True:
        raw = ser.readline()
        if not raw:
            continue

        text = safe_strip_line(raw)

        try:
            process_line(text)
        except Exception as e:
            print(f"[!] Parse/crypto error: {e}")
            print("--------------------------------\n")


# =========================
# LANCEMENT
# =========================
if __name__ == "__main__":
    main()
