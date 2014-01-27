#!/usr/bin/python

import socket
import dpkt
import struct

s = socket.socket(socket.PF_PACKET, socket.SOCK_RAW, socket.htons(0x0800))
SECRET_LEN = 64

def get_msg(data):
    if len(data) < 48:
        return ''
    ctext = data[48:]
    cidx = 0
    out = ""

    print 'ctext: %s' % ctext.encode('hex')
    while cidx < len(ctext):
        ca, cb, cc, cd = struct.unpack('!BBBB', ctext[cidx:cidx+4])
        print 'ca = %02x, cb = %02x, cc = %02x, cd = %02x' % (ca, cb, cc, cd)
        x = (ca & 0x3f)*(64**3) + (cb & 0x3f)*(64**2) + (cc & 0x3f)*(64) + (cd & 0x3f)
        print 'x = %08x' % x
        # now encode x in 3 bytes
        out += struct.pack('!I', x)[1:]
        cidx += 4

    return out[0:SECRET_LEN]

while True:
    pkt = s.recv(0x1000)
    eth = dpkt.ethernet.Ethernet(pkt)
    ip = eth.data
    if ip.p == dpkt.ip.IP_PROTO_TCP:
        tcp = ip.data
        if ip.dst == socket.inet_aton('141.212.108.13') and tcp.dport == 443:
            #print '%d, %s' % (len(tcp.data), ip.__repr__())
            if len(tcp.data) > 13:
                if tcp.data[0] == '\x17':
                    #print 'data: ', tcp.data
                    # App data
                    enc_payload = tcp.data[5:]
                    #iv = enc_payload[0:8]
                    data = enc_payload[8:]
                    msg = get_msg(data)
                    print 'secret message: %s:\n%s' % (msg.encode('hex'), msg)



