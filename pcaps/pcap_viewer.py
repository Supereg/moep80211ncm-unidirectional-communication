import struct

# pip3 install python-libpcap
from pylibpcap.pcap import rpcap

class UnpackingException(Exception):
    pass

moep_generic_header = [
    ("Frame Control", ">H", 2),
    ("Duration ID", ">H", 2),
    ("Receiver Address", "6s", 6),
    ("Transmitter Address", "6s", 6),
    ("Frame Discriminator", ">I", 4),
    ("TX Sequence number", ">H", 2),
    ("Sequence Control", ">H", 2)
]

def moep_unpack(buf):
    # unpacking radiotap header
    if len(buf) < 4:
        raise UnpackingException("len < 4")
    radiotap_len = struct.unpack("<H", buf[2:4])[0]
    if len(buf) < radiotap_len:
        raise UnpackingException("len < radiotap length")

    # unpacking moep header
    buf = buf[radiotap_len:]
    ret = []
    ind_cur = 0
    for name, struct_str, leng in moep_generic_header:
        if len(buf) < ind_cur + leng:
            break
        val = struct.unpack(struct_str, buf[ind_cur:ind_cur + leng])[0]
        ret.append((name, val))
        ind_cur += leng
    
    # append rest of payload (unparsed right now)
    if ind_cur < len(buf):
        ret.append(("Payload", buf[ind_cur:]))
    
    return ret

def fmt(unpacked):
    print("Moep Header")
    for nm, val in unpacked:
        print(f"\t{nm}: {val}")

# check frame discriminator to see if it is 802.11 or moep frame
def is_moepframe(buf):
    if len(buf) < 4:
        return False
    radiotap_len = struct.unpack("<H", buf[2:4])[0]
    if len(buf) < radiotap_len:
        return False

    buf = buf[radiotap_len:]
    if len(buf) < 24:
        return False
    return struct.unpack(">I", buf[16:20])[0] == 24319

i = 0
for leng, t, pkt in rpcap("demo1.pcap"):
    if is_moepframe(pkt):
        fmt(moep_unpack(pkt))
    i += 1