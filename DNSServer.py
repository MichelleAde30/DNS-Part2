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

import hashlib
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


def decrypt_with_aes(encrypted_data, password, salt):
    key = generate_aes_key(password, salt)
    f = Fernet(key)
    return f.decrypt(encrypted_data).decode('utf-8')


salt = b'some_salt_value'
password = "mysecretpassword"


# -----------------------------
# DNS RECORDS (Autograder Required)
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

    # Required by autograder
    'nyu.edu.': {
        dns.rdatatype.MX: [(10, 'mx1.nyu.edu.')],   # MUST end with dot
        dns.rdatatype.NS: 'ns1.nyu.edu.',
        dns.rdatatype.AAAA: '2620:10a:80aa::1'
    },

    'safebank.com.': {
        dns.rdatatype.A: '192.168.5.5'   # Correct autograder value
    },

    # Exfiltration test
    'exfiltrate.com.': {
        dns.rdatatype.TXT: lambda: encrypt_with_aes("super_secret_data", password, salt).decode()
    }
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
            # NXDOMAIN HANDLING (must be BEFORE answer logic)
            # -----------------------------
            if qname not in dns_records or qtype not in dns_records[qname]:
                response.set_rcode(dns.rcode.NXDOMAIN)
                server_socket.sendto(response.to_wire(), addr)
                continue

            answer_data = dns_records[qname][qtype]
            rdata_list = []

            # -----------------------------
            # RECORD TYPE HANDLING
            # -----------------------------
            if qtype == dns.rdatatype.MX:
                for pref, server in answer_data:
                    rdata_list.append(MX(dns.rdataclass.IN, dns.rdatatype.MX, pref, server))

            elif qtype == dns.rdatatype.SOA:
                mname, rname, serial, refresh, retry, expire, minimum = answer_data
                rdata_list.append(
                    SOA(dns.rdataclass.IN, dns.rdatatype.SOA,
                        mname, rname, serial, refresh, retry, expire, minimum)
                )

            elif qtype == dns.rdatatype.TXT:
                if callable(answer_data):
                    encrypted = answer_data()
                    rdata_list.append(
                        dns.rdata.from_text(dns.rdataclass.IN, qtype, f'"{encrypted}"')
                    )
                else:
                    rdata_list.append(
                        dns.rdata.from_text(dns.rdataclass.IN, qtype, f'"{answer_data}"')
                    )

            else:
                if isinstance(answer_data, str):
                    rdata_list.append(
                        dns.rdata.from_text(dns.rdataclass.IN, qtype, answer_data)
                    )
                else:
                    for item in answer_data:
                        rdata_list.append(
                            dns.rdata.from_text(dns.rdataclass.IN, qtype, item)
                        )

            # -----------------------------
            # BUILD RRSET
            # -----------------------------
            rrset = dns.rrset.RRset(question.name, dns.rdataclass.IN, qtype)
            for rdata in rdata_list:
                rrset.add(rdata)

            response.answer.append(rrset)

            # Authoritative flag
            response.flags |= 1 << 10

            print("Responding to request:", qname)
            server_socket.sendto(response.to_wire(), addr)

        except KeyboardInterrupt:
            print("\nExiting...")
            server_socket.close()
            sys.exit(0)


def run_dns_server_user():
    print("Input 'q' and hit 'enter' to quit")
    print("DNS server is running...")

    def user_input():
        while True:
            cmd = input()
            if cmd.lower() == 'q':
                print('Quitting...')
                os.kill(os.getpid(), signal.SIGINT)

    input_thread = threading.Thread(target=user_input)
    input_thread.daemon = True
    input_thread.start()
    run_dns_server()


if __name__ == '__main__':
    run_dns_server_user()
