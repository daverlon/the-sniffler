from scapy.all import sniff, IP, UDP, Packet
import subprocess
from lzss import decompress
import ctypes
import struct
import binascii
import sys

SAMPLE_PACKET = "c70d0000d00c000021c8ba00ae7c1ede8823c137bf200430c6f6951776370757564606f0d12f0801a4b97dd5cd95ad95e589bd85c991cd85b5c1b195d1a5b595017cf50b42006d5f796177009ffd821040db97591a1b5d991cc077bf2004d0f635563747f7d616363656c606f0e12f0801b47dc985dda5b9c1d5d1017cf90b420073656e7369746976697479009ffe821080da5bde575ed8dd5c99db5c1a5d9a5d1a5d1ec0b7bf2004a0f69637479736b606f0f12f0801e8bdbdb57dcd95b9cda5d1a5d9a5d1e57dc985d1a5bd015c1710800188aa458ab94301a83182d10f226a141055ab1461870250639ca33864d72620aa9628e20e05a0c6f846e50fac394054ad88d41d0a408dd18cb0546f7380a85a13c93b14801ae31925ae16b70151b542f176280035462a5a7f99cd01a26a7da2ed50006a8c7bbcfee89b0344d5c244d8a100d41be358ff75fe0488aa9589b14301a8315ed1fbdb7b101055ab136b87025063a4e2fd07e92020aad643c20e05a0c698c729c9af5d40542d88841d0a408dd18b23935f9b80a85a15d93b14801aa31f85ad72070151b5247277280035c637ca587ced02a26a6de2ec50006a8c7be4fe781e0444d5f244dba100d418b318ff3d390788aa058ab64301a831e6d1fb6b6e0e10554b1365870250636422fca7f52020aa9629c20e05a0c6f8c59988b94140542d4ea41d0a408d718de45fb57b80a85a0e293b14801a631eb123ec060151b5287276280035c637165c810e03ae41466201207ec00140cb491689058003080e000c599cde4600a2ff11daed53335c60076e12009935000060100000601000009ed08000000083000000830000f084b60e004235120b00311c80"

NETMSG_TYPE_BITS = 6	# must be 2^NETMSG_TYPE_BITS > SVC_LASTMSG
NET_MAX_PAYLOAD = 524284

NET_HEADER_FLAG_QUERY = -1 # 0xFFFFFFFF
NET_HEADER_FLAG_SPLITPACKET = -2 # 0xFFFFFFFE
NET_HEADER_FLAG_COMPRESSEDPACKET = -3 # 0xFFFFFFFD

# possibly outdated?
"""
enum SVC_Messages
{
	svc_ServerInfo 			= 8;		// first message from server about game; map etc
	svc_SendTable 			= 9;		// sends a sendtable description for a game class
	svc_ClassInfo 			= 10;		// Info about classes (first byte is a CLASSINFO_ define).							
	svc_SetPause 			= 11;		// tells client if server paused or unpaused
	svc_CreateStringTable 	= 12;		// inits shared string tables
	svc_UpdateStringTable 	= 13;		// updates a string table
	svc_VoiceInit 			= 14;		// inits used voice codecs & quality
	svc_VoiceData 			= 15;		// Voicestream data from the server
	svc_Print 				= 16;		// print text to console
	svc_Sounds 				= 17;		// starts playing sound
	svc_SetView 			= 18;		// sets entity as point of view
	svc_FixAngle 			= 19;		// sets/corrects players viewangle
	svc_CrosshairAngle 		= 20;		// adjusts crosshair in auto aim mode to lock on traget
	svc_BSPDecal 			= 21;		// add a static decal to the world BSP
	svc_UserMessage 		= 23;		// a game specific message 
	svc_GameEvent 			= 25;		// global game event fired
	svc_PacketEntities 		= 26;		// non-delta compressed entities
	svc_TempEntities 		= 27;		// non-reliable event object
	svc_Prefetch 			= 28;		// only sound indices for now
	svc_Menu 				= 29;		// display a menu from a plugin
	svc_GameEventList 		= 30;		// list of known games events and fields
	svc_GetCvarValue 		= 31;		// Server wants to know the value of a cvar on the client	
}
"""

PACKET_FLAG_RELIABLE = 1 << 0
PACKET_FLAG_COMPRESSED = 1 << 1
PACKET_FLAG_ENCRYPTED = 1 << 2
PACKET_FLAG_SPLIT = 1 << 3
PACKET_FLAG_CHOKED = 1 << 4
PACKET_FLAG_CHALLENGE = 1 << 5
PACKET_FLAG_TABLES = 1 << 10 #custom flag, request string tables
"""
    is_reliable = (flags & PACKET_FLAG_RELIABLE) != 0
    is_compressed = (flags & PACKET_FLAG_COMPRESSED) != 0
    is_encrypted = (flags & PACKET_FLAG_ENCRYPTED) != 0
    is_split = (flags & PACKET_FLAG_SPLIT) != 0
    is_challenge = (flags & PACKET_FLAG_CHALLENGE) != 0
"""

target_ip = "139.99.136.174" # griver
target_ip = "203.209.209.92" # griver? (snakoo pub?)
target_ip = "203.209.209.92" # bhop
# target_ip = "67.219.97.72" # trikz
log_file_path = "packet_log.txt"

# 0xFF_FF_FF_FF (or -1)

NET_HEADER_FLAG_QUERY = -1
NET_HEADER_FLAG_SPLITPACKET = -2
NET_HEADER_FLAG_COMPRESSEDPACKET = -3

def format_hex(s): return ' '.join(s[i:i+2] for i in range(0, len(s), 2))

DECRYPT_APP = "icekey.exe"
DECOMPRESS_APP = "lzss.exe"

# default
icekey_n = str(2)
icekey_key = "d7NSuLq2"

# kamay proxycheat
icekey_key = str(bytes([0x43, 0x53, 0x47, 0x4f, 0x87, 0x35, 0x00, 0x00,
                       0x61, 0x0d, 0x00, 0x00, 0x58, 0x03, 0x00, 0x00]))

newest_seqnum = 0
newest_challenge = 0
in_reliable_state = 0

unique_msgs = set()

# from src
# icekey_n = str(1)
# icekey_key = str(bytes([191, 1, 0, 222, 85, 39, 154, 1]))

# icekey_n = str(1)
# icekey_key = str(bytes([4, 175, 165, 5, 76, 251, 29, 113]))

# icekey_n = str(1)
# icekey_key = str(bytes([200,145,10,149,195,190,108,243]))

"""

    some keys from the leaked source

    IceKey cipher(1); /* medium encryption level */
    unsigned char ucEncryptionKey[8] = { 191, 1, 0, 222, 85, 39, 154, 1 };
    > engine\host_phonehome.cpp

    IceKey cipher(1); /* medium encryption level */
	unsigned char ucEncryptionKey[8] = { 54, 175, 165, 5, 76, 251, 29, 113 };    
    > engine\sv_uploaddata.cpp

    IceKey cipher(1); /* medium encryption level */
	unsigned char ucEncryptionKey[8] = { 200,145,10,149,195,190,108,243 };
    > utils\bugreporter_public\bugreporter_upload.cpp

"""

def decryptblock(hexstring: str) -> str:
    # 16 hex chars
    if len(hexstring) > 16:
        print("Error: Hex string larger than block size (8)") 
        return

    # icekey.exe 2 d7NSuLq2 1a1b1c1d1a1b1c1d
    cmd = DECRYPT_APP + " " + icekey_n + " " + icekey_key + " " + hexstring
    
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
    cmd = DECOMPRESS_APP + " " + hexstring
    result = subprocess.check_output(cmd, shell=True, text=True)
    # print(cmd + " ---> " + result)
    if "YYY" in result:
        print("FOUND COMPRESSED PACKET")
        exit()
    return result

# retrieve bytes from the beginning of the bytes array
# then remove them & return
def extract_bytes(payload: bytes, n_bytes: int):
    return payload[:n_bytes], payload[n_bytes:]

def flip_bit(v, b):
    if v & b:
        v &= ~b
    else:
        v |= b
    return v

def pad_bytes(payload: bytes):
    l = len(payload) % 8
    xtra = 8 - l
    payload = payload + bytes([0] * xtra)
    return payload

def get_number_of_remaining_bits(payload: bytes): return sys.getsizeof(payload)

def read_ubit_long(data, n_bits):
    index = 0
    bits_avail = 0
    current_word = 0

    def fetch_next():
        nonlocal index, bits_avail, current_word
        if index < len(data):
            current_byte = data[index]
            current_word |= current_byte << bits_avail
            bits_avail += 8
            return True
        return False

    def grab_next_dword():
        nonlocal index, current_word
        if index + 3 < len(data):
            dword = int.from_bytes(data[index:index + 4], byteorder='little')
            current_word |= dword << bits_avail
            index += 4

    result = 0

    while bits_avail < n_bits:
        if not fetch_next():
            raise ValueError("Not enough bits in the data")

    result = current_word & ((1 << n_bits) - 1)
    current_word >>= n_bits
    bits_avail -= n_bits

    if bits_avail == 0:
        fetch_next()
    elif index < len(data):
        grab_next_dword()

    consumed_bytes = (index * 8 - bits_avail) // 8
    remaining_data = data[consumed_bytes:]

    return result, remaining_data

def decodepacket(payload: bytes):

    # check for query flag
    qhdr = payload[:4]
    print("Header:", qhdr)
    if qhdr == b'\xff\xff\xff\xff':
        print("[Found OOB Query]")

        connectiontype_type = ctypes.c_char
        connectiontype_bytes, _ = extract_bytes(payload[4:], ctypes.sizeof(connectiontype_type))
        connectiontype = connectiontype_type.from_buffer_copy(connectiontype_bytes)
        print("Connection type:", connectiontype.value)

        print("Skipping OOB Query packet.")
        return
    
    if qhdr == b'\xff\xff\xff\xfe':
        print("[Found Split Packet]")
        return
    
    if qhdr == b'\xff\xff\xff\xfd':
        print("[Found Compressed Packet]")
        return

    global newest_seqnum
    global in_reliable_state
    global unique_msgs

    # decode header

    seqnum_type = ctypes.c_uint32
    seqacknum_type = ctypes.c_uint32
    flags_type = ctypes.c_uint8
    checksum_type = ctypes.c_ushort
    
    # Extract and create instances using from_buffer_copy
    seqnum_bytes, payload = extract_bytes(payload, ctypes.sizeof(seqnum_type))
    seqnum = seqnum_type.from_buffer_copy(seqnum_bytes)

    seqacknum_bytes, payload = extract_bytes(payload, ctypes.sizeof(seqacknum_type))
    seqacknum = seqacknum_type.from_buffer_copy(seqacknum_bytes)

    flags_bytes, payload = extract_bytes(payload, ctypes.sizeof(flags_type))
    flags = flags_type.from_buffer_copy(flags_bytes)

    checksum_bytes, payload = extract_bytes(payload, ctypes.sizeof(checksum_type))
    checksum = checksum_type.from_buffer_copy(checksum_bytes)

    # Now seqnum, seqacknum, flags, checksum are ctypes instances with correct values
    print(f"seqnum: {seqnum.value}")
    print(f"seqacknum: {seqacknum.value}")
    print(f"flags: {format(flags.value, '08b')}")

    # if payload[0] == b'\x00':
    #     _, payload = extract_bytes(payload, 1)

    # checksum
    # _, payload = extract_bytes(payload, 1)
    offset = payload[0] >> 3
    chck = do_checksum(payload, offset)
    _, payload = extract_bytes(payload, 1)
    print(f"checksum: {checksum.value} --- {chck}")
    if checksum.value != chck:
        print("Checksum mismatch. Datagram invalid.")
        return

    # relstate (reliability) (1 byte)
    relstate, payload = extract_bytes(payload, 1)

    # nChoked = 0
    if flags.value & PACKET_FLAG_CHOKED:
        print("CHOKED.")
        nchoked, payload = extract_bytes(payload, 1)

    if seqnum.value <= newest_seqnum:
        print("Out of order packet.")
        # return
        # print("Discarding packet with older sequence num.")
        # return
    newest_seqnum = seqnum.value

    challenge = None
    if flags.value & PACKET_FLAG_CHALLENGE:
        challenge_type = ctypes.c_uint32
        chbytes, payload = extract_bytes(payload, ctypes.sizeof(challenge_type))
        challenge = challenge_type.from_buffer_copy(chbytes)
        print("\tnChallenge:", challenge.value)

    if seqnum.value == 0x36:
        flags.value |= PACKET_FLAG_TABLES

    if flags.value & PACKET_FLAG_COMPRESSED:
        print("$ COMPRESSED PACKET $")

    if flags.value & PACKET_FLAG_COMPRESSED:
        print("$ ENCRYPTED PACKET $")
    
    if flags.value & PACKET_FLAG_CHALLENGE:
        print("$ CHALLENGE PACKET $")

    if flags.value & PACKET_FLAG_SPLIT:
        print("$ SPLIT PACKET $")


    if flags.value & PACKET_FLAG_RELIABLE:
        print("$ RELIABLE PACKET $")

        bit, payload = read_ubit_long(payload, 3)

        bit = 1 << bit
        # print("Bit:", bit)

        in_reliable_state = flip_bit(in_reliable_state, bit)
        # print("Remaining bits:", get_number_of_remaining_bits(payload))

        # decode msgs
        print('-'*20)
        while True:
            print("Remaining payload:")
            print(payload, len(payload))
            if get_number_of_remaining_bits(payload) < NETMSG_TYPE_BITS:
                break

            def read_varint32(encoded_bytes):
                result = 0
                shift = 0
                count = 0
                for byte in encoded_bytes:
                    result |= (byte & 0x7F) << shift
                    shift += 7
                    count += 1
                    if not byte & 0x80:
                        print("* Found 0x80")
                        break
                    elif count >= 5:
                        print("* Max bytes reached.")
                        break
                print(f"* Consumed {count} bytes.")
                return result, encoded_bytes[count:]

            msg, payload = read_ubit_long(payload, NETMSG_TYPE_BITS)
            print("Msg id:", msg)
            print("Msg id (bytes):", format(msg, '08b'))
            unique_msgs.add(msg)

            bufsize, payload = read_varint32(payload)
            print("Msg size:", bufsize)
            print("Remaining bits/bytes:", get_number_of_remaining_bits(payload), get_number_of_remaining_bits(payload)//8)

            if bufsize < 0 or bufsize > NET_MAX_PAYLOAD:
                print("*** Break:", bufsize)
                break 
            if bufsize > get_number_of_remaining_bits(payload)//8:
                print(f"*** Break msg size larger than remaining bytes: {bufsize}/{get_number_of_remaining_bits(payload)//8}")
                break

            # payload = pad_bytes(payload)

            msg_payload = payload[:bufsize]
            print("Msg payload:", msg_payload)

            payload = payload[bufsize:]

            # message CSVCMsg_GetCvarValue
            # {
            #     optional int32 cookie = 1;		// QueryCvarCookie_t
            #     optional string cvar_name = 2;
            # }
            # if msg == 31:
            #     print("GetCvarValue")
            #     cookieint = ctypes.c_uint32
            #     cookie_bytes, payload = extract_bytes(payload, ctypes.sizeof(cookieint))
            #     cookie = cookieint.from_buffer_copy(cookie_bytes)
            #     print(cookie.value)

            #     x, payload = (payload)
            #     print(x)


            # print(decompresspayload(payload[:bufsize+1].hex()))
            # print(decompresspayload(''.join(decryptall(payload[:bufsize].hex()))))
            print('-'*20)

        print(unique_msgs)
            
            

            








    
    
def do_checksum(data, offset):
    checksum = binascii.crc32(data[offset:]) & 0xFFFFFFFF
    lower_word = checksum & 0xFFFF
    upper_word = (checksum >> 16) & 0xFFFF
    return lower_word ^ upper_word


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

            decodepacket(bytes.fromhex(payload_hex))
            print("Newest seq:", newest_seqnum)


            





if __name__ == "__main__":
    # bytes_data = bytes([0x12, 0x13, 0x14, 0x15, 0x12, 0x13, 0x14, 0x15])
    # print(ice.Decrypt(bytes_data))


    # sniff(prn=packet_callback, store=0)

    decodepacket(bytes.fromhex(SAMPLE_PACKET))

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