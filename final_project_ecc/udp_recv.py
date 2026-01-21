import socket

s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.bind(("0.0.0.0", 1234))

print("Listening UDP on port 1234...")

while True:
    data, addr = s.recvfrom(4096)
    print("FROM", addr)
    print("LEN", len(data))
    print("HEX", data.hex().upper())
    print()
