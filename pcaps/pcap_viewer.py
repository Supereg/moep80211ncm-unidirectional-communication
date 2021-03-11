import struct

# pip3 install python-libpcap
from pylibpcap.pcap import rpcap

# Moep extension header types
HDR_PCTRL = 0x01
HDR_DATA = 0x20
HDR_CODED = 0x21
HDR_BCAST = 0x22
HDR_BEACON = 0x23

# Moep extension header type lookup table
hdr_types = {
    0x01: "HDR_PCTRL",
    0x20: "HDR_DATA",
    0x21: "HDR_CODED",
    0x22: "HDR_BCAST",
    0x23: "HDR_BEACON"
}

# custom Exception to raise during unpacking
class UnpackingException(Exception):
    pass

# format MAC addresses
def fmt_mac(addr):
    return ":".join([hex(el)[2:] for el in addr])

# format header types/Flags prettily
def fmt_type(tpe, tps):
    try:
        return f"{hex(tpe)} ({tps[tpe]})"
    except KeyError:
        return f"{hex(tpe)} (Unknown)"

# do nothing
def nop(x):
    return x

# unpack header type with flags
def unpack_hdrtype(buf):
    bufval = struct.unpack(">B", buf[:1])[0]
    res = (bufval & 0x80) >> 7
    nxt = (bufval & 0x40) >> 6
    priv = (bufval & 0x20) >> 5
    typeval = bufval & 0xbf
    return [
        ("Reserved", res, hex),
        ("NEXT", nxt, hex),
        ("Private", priv, hex),
        ("Type", typeval, lambda x: fmt_type(x, hdr_types))
    ]

# Header structures
# Name, struct unpacking format, length, printing format

moep_generic_header = [
    ("Frame Control", ">H", 2, hex),
    ("Duration ID", ">H", 2, hex),
    ("Receiver Address", "6s", 6, fmt_mac),
    ("Transmitter Address", "6s", 6, fmt_mac),
    ("Frame Discriminator", ">I", 4, hex),
    ("TX Sequence number", ">H", 2, hex),
    ("Sequence Control", ">H", 2, hex)
]

moep_ext_header = [
    ("Ext Type + Flags", unpack_hdrtype, 1, hex),
    ("Ext Len", ">B", 1, hex)
]

moep_hdr_pctrl = [
    ("Type", ">H", 2, hex),
    ("Len", ">H", 2, hex)
]

moep_hdr_coded = [
    ("SID1", "6s", 6, fmt_mac),
    ("SID2", "6s", 6, fmt_mac),
    ("GF", "B", 1, hex),
    ("Window Size", "B", 1, hex),
    ("seq", ">H", 2, hex),
    ("lseq", ">H", 2, hex)
]

moep_struct_generation_feedback = [
    ("ms_lock", "B", 1, hex),
    ("sm_lock", "B", 1, hex),
    ("unused", "B", 1, hex),
    ("ms_ddim", "B", 1, hex),
    ("sm_ddim", "B", 1, hex),
    ("ms_sdim", "B", 1, hex),
    ("sm_sdim", "B", 1, hex),
]

moep_hdr_beacon = [
    ("mac", "6s", 6, fmt_mac),
    ("p", ">H", 2, hex),
    ("q", ">H", 2, hex)
]

moep_hdr_bcast = [
    ("id", ">I", 4, hex)
]

# unpacking generic headers following above structures
def unpack_generic(buf, hdr):
    ret = []
    ind_cur = 0
    for name, struct_str, leng, fmt in hdr:
        if len(buf) < ind_cur + leng:
            raise UnpackingException("hdr short")
        if isinstance(struct_str, str):
            val = struct.unpack(struct_str, buf[ind_cur:ind_cur + leng])[0]
            ret.append((name, val, fmt))
        else:
            vals = struct_str(buf[ind_cur:])
            ret += vals
        ind_cur += leng
    return ret, ind_cur

# unpack moep frame
def moep_unpack(buf):
    # unpacking radiotap header
    if len(buf) < 4:
        raise UnpackingException("len < 4")
    radiotap_len = struct.unpack("<H", buf[2:4])[0]
    if len(buf) < radiotap_len:
        raise UnpackingException("len < radiotap length")

    buf = buf[radiotap_len:]
    ret = []
    ind_cur = 0
    
    # unpacking moep header
    ret_app, ind_new = unpack_generic(buf[ind_cur:], moep_generic_header)
    ret.append(("Moep Header", ret_app))
    ind_cur += ind_new

    # unpacking moep ext headers
    nex_hdr = 1
    while nex_hdr:
        ret_app, ind_new = unpack_generic(buf[ind_cur:], moep_ext_header)
        ret.append(("Moep Ext Header", ret_app))
        ind_cur += ind_new
        nex_hdr = ret[-1][1][1][1]
        hdr_type = ret[-1][1][3][1]
        hdr_len = ret[-1][1][4][1]

        if hdr_type == HDR_PCTRL:
            ret_app, ind_new = unpack_generic(buf[ind_cur:], moep_hdr_pctrl)
            payload_len = ret_app[1][1]
            ind_cur += ind_new
            ret.append(("PCtrl Header", ret_app))
        elif hdr_type == HDR_CODED:
            ret_coded, ind_new = unpack_generic(buf[ind_cur:], moep_hdr_coded)
            ind_cur += ind_new

            coded_len = ind_new
            while coded_len < hdr_len:
                # Acknowlegment?? ToDo: figure out different header lenghts...
                if len(buf[ind_cur:]) < 7:
                    break
                ret_app, ind_new = unpack_generic(buf[ind_cur:], moep_struct_generation_feedback)
                ind_cur += ind_new
                ret_coded += ret_app
                coded_len += ind_new

            ret.append(("Coded Header", ret_coded))
        elif hdr_type == HDR_BEACON:
            ret_app, ind_new = unpack_generic(buf[ind_cur:], moep_hdr_beacon)
            ind_cur += ind_new
            ret.append(("Beacon Header", ret_app))
        elif hdr_type == HDR_BCAST:
            ret_app, ind_new = unpack_generic(buf[ind_cur:], moep_hdr_bcast)
            ind_cur += ind_new
            ret.append(("Broadcast Header", ret_app))
        else:
            break
    
    # append rest of payload (unparsed right now)
    if ind_cur < len(buf):
        ret.append(("Payload", [("Payload", buf[ind_cur:], nop)]))
    
    return ret

# format unpacked frame
def fmt(unpacked):
    for hdr, vals in unpacked:
        print(hdr)
        for nm, val, fmt in vals:
            print(f"\t{nm}: {fmt(val)}")

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
        print()
    i += 1