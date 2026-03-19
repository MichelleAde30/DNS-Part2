import dns.message
import dns.rdatatype
import dns.rdataclass
from dns.rdtypes.ANY.MX import MX
from dns.rdtypes.ANY.SOA import SOA
import dns.rdata
import socket
import threading
import signal
import os
import sys

from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import base64


# -----------------------------
# AES ENCRYPTION HELPERS
# -----------------------------

def generate_aes_key(password, salt):
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        iterations=100000,
        salt=salt,
        length=32
    )
    key = kdf.derive(password.encode('utf-8'))
    return base64.urlsafe_b64encode(key)


def encrypt_with_aes(input_string, password, salt):
    key = generate_aes_key(password, salt)
    f = Fernet(key)
    return f.encrypt(input_string.encode('utf-8'))


# -----------------------------
# EXFILTRATION PARAMETERS
# -----------------------------

salt = b"Tandon"
password = "ma10064@nyu.edu"
input_string = "AlwaysWatching"

encrypted_value = encrypt_with_aes(input_string, password, salt)


# -----------------------------
# DNS RECORDS
# -----------------------------

dns_records = {
    'example.com.': {
        dns.rdatatype.A: '192.168.1.101',
        dns.rdatatype.AAAA: '2001:0db8:85a3:0000:0000:8a2e:0370:7334',
        dns.rdatatype.MX: [(10, 'mail.example.com.')],
        dns.rdatatype.CNAME: 'www.example.com.',
        dns.rdatatype.NS: 'ns.example.com.',
        dns.rdatatype.TXT: ('This is a TXT record',),
        dns.rdatatype.SOA: (
            'ns1.example.com.',
            'admin.example.com.',
            2023081401,
            3600,
            1800,
            604800,
            86400,
        ),
    },

    'safebank.com.': {dns.rdatatype.A: '192.168.1.102'},
    'google.com.': {dns.rdatatype.A: '192.168.1.103'},
    'legitsite.com.': {dns.rdatatype.A: '192.168.1.104'},
    'yahoo.com.': {dns.rdatatype.A: '192.168.1.105'},

    'nyu.edu.': {
        dns.rdatatype.A: '192.168.1.106',
        dns.rdatatype.TXT: (encrypted_value.decode('utf-8'),),
        dns.rdatatype.MX: [(10, 'mxa-00256a01.gslb.pphosted.com.')],
        dns.rdatatype.AAAA: '2001:0db8:85a3:0000:0000:8a2e:0373:7312',
        dns.rdatatype.NS: 'ns1.nyu.edu.'
    },
}


# -----------------------------
# DNS SERVER LOOP
# -----------------------------

def run_dns_server():
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    server_socket.bind(("127.0.0.1", 53))

    while True:
        try:
            data, addr = server_socket.recvfrom(1024)
            request = dns.message.from_wire(data)
            response = dns.message.make_response(request)

            question = request.question[0]
            qname = question.name.to_text()
            qtype = question.rdtype

            # -----------------------------
            # NXDOMAIN HANDLING
            # -----------------------------
            if qname not in dns_records or qtype not in dns_records[qname]:
                response.set_rcode(dns.rcode.NXDOMAIN)
                response.flags |= 1 << 10  # authoritative
                server_socket.sendto(response.to_wire(), addr)
                continue

            answer_data = dns_records[qname][qtype]
            rdata_list = []

            # -----------------------------
            # RECORD TYPE HANDLING
            # -----------------------------
            if qtype == dns.rdatatype.MX:
                for pref, server in answer_data:
                    rdata_list.append(
                        MX(dns.rdataclass.IN, dns.rdatatype.MX, pref, server)
                    )

            elif qtype == dns.rdatatype.SOA:
                mname, rname, serial, refresh, retry, expire, minimum = answer_data
                rdata_list.append(
                    SOA(
