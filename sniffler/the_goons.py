from scapy.all import sniff, IP, UDP, Packet
import subprocess
from lzss import decompress


# target_ip = "139.99.136.174" # griver
# target_ip = "203.209.209.92" # griver
target_ip = "203.209.209.92" # bhop
log_file_path = "packet_log.txt"

# 0xFF_FF_FF_FF (or -1)

NET_HEADER_FLAG_QUERY = -1
NET_HEADER_FLAG_SPLITPACKET = -2
NET_HEADER_FLAG_COMPRESSEDPACKET = -3

def format_hex(s): return ' '.join(s[i:i+2] for i in range(0, len(s), 2))

DECRYPT_APP = "ciekey.exe"

def decryptblock(hexstring: str) -> str:
    # 16 hex chars
    if len(hexstring) > 16:
        print("Error: Hex string larger than block size (8)") 
        return
    cmd = DECRYPT_APP + " decrypt " + hexstring
    result = subprocess.check_output(cmd, shell=True, text=True)
    # print(cmd + " ---> " + result)
    # print(f'assert(decryptblock("{hexstring}")=="{result}")')
    # assert(decryptblock(hexstring)=="{result}") # recursion problem <---
    return result

def decryptall(hexstring: str) -> []:
    ret = []
    size = len(hexstring)
    cur = 0
    block_size = 16
    while (size - cur) >= block_size:
        curblock = hexstring[cur:cur+block_size]
        result = decryptblock(curblock)
        ret.append(result)
        cur += 16
    return ret

def decompresspayload(hexstring: str):
    # full packet
    cmd = DECRYPT_APP + " decompress " + hexstring
    result = subprocess.check_output(cmd, shell=True, text=True)
    # print(cmd + " ---> " + result)
    if "Not" not in result:
        print("FOUND COMPRESSED PACKET")
        exit()
    return result


def packet_callback(packet: Packet):
    if IP in packet and UDP in packet:
        if packet[IP].src == target_ip or packet[IP].dst == target_ip:

            print("="*50)

            payload_hex = packet.payload.load.hex()
            decrypted_hex = decryptall(payload_hex)

            # packet summary
            # print()
            print("Packet:", packet.summary())
            print()

            # packet in hex
            print("Payload (hex):")
            print(payload_hex)

            print()
            print("Payload (bytes)")
            print(bytes.fromhex(payload_hex))

            print()
            print("Payload (hex decrypted):")
            print(''.join(decrypted_hex))
            print()

            print("Payload (bytes decrypted):")
            decrypted_bytes = bytes.fromhex(''.join(decrypted_hex))
            print(decrypted_bytes)

            print()
            print(decompresspayload(''.join(decrypted_hex)))
            print(decompresspayload(payload_hex))

            # print("Payload (bytes decompressed)")
            # decompressed_bytes = decompress(decrypted_bytes)
            # print(decompressed_bytes)
            # decompresspayload(''.join(payload_hex))
            # decompresspayload(str(decrypted_bytes))

            





if __name__ == "__main__":
    # bytes_data = bytes([0x12, 0x13, 0x14, 0x15, 0x12, 0x13, 0x14, 0x15])
    # print(ice.Decrypt(bytes_data))
    sniff(prn=packet_callback, store=0)

    # test decryption
    exit()
    hx = "495a0600e659060020a47500e0793e1c43ad9601c0128112806688ac5a0600030004000842b75a0600311380"
    print(decryptall(hx))

    assert(decryptblock("495a0600e6590600")=="06adcda07f127916")
    assert(decryptblock("495a0600e6590600")=="06adcda07f127916")
    assert(decryptblock("20a47500e0793e1c")=="b9fa010e833f2684")
    assert(decryptblock("43ad9601c0128112")=="51840bc120fe4b25")
    assert(decryptblock("806688ac5a060003")=="69ee1ff5d91f1c49")
    assert(decryptblock("0004000842b75a06")=="489296d1ba1320a6")