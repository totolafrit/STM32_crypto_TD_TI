import serial
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

PORT = "COM3"      # <-- change
BAUD = 115200

def read_line(ser):
    return ser.readline().decode(errors="ignore").strip()

def hex_to_bytes(h): return bytes.fromhex(h)
def bytes_to_hex(b): return b.hex().upper()

ser = serial.Serial(PORT, BAUD, timeout=5)
ser.reset_input_buffer()

# 1) Lire la PUB STM32
while True:
    line = read_line(ser)
    if not line:
        continue
    print("STM32:", line)
    if line.startswith("PUB:"):
        stm_hex = line[4:]
        break

stm_pub_bytes = hex_to_bytes(stm_hex)

# 2) Générer clé ECC PC
pc_priv = ec.generate_private_key(ec.SECP256R1())
pc_pub = pc_priv.public_key().public_bytes(Encoding.X962, PublicFormat.UncompressedPoint)

# 3) Envoyer PUB PC
pc_hex = bytes_to_hex(pc_pub)
msg = "PUB:" + pc_hex + "\r\n"
ser.write(msg.encode())
print("PC -> STM32:", msg.strip())

# 4) Calculer secret côté PC
stm_pub = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), stm_pub_bytes)
pc_secret = pc_priv.exchange(ec.ECDH(), stm_pub)
print("PC SECRET:", bytes_to_hex(pc_secret))

# 5) Lire SECRET STM32 et comparer
while True:
    line = read_line(ser)
    if not line:
        continue
    print("STM32:", line)
    if line.startswith("SECRET:"):
        stm_secret = hex_to_bytes(line[7:])
        break

print("MATCH:", stm_secret == pc_secret)
