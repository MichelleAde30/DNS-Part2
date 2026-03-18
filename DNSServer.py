import dns.message
import dns.rdatatype
import dns.rdataclass
import dns.rdtypes
import dns.rdtypes.ANY
from dns.rdtypes.ANY.MX import MX
from dns.rdtypes.ANY.SOA import SOA
import dns.rdata
import dns.rrset
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
import ast


# --- AES FUNCTIONS (fill required blanks) ---
def generate_aes_key(password, salt):
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        iterations=100000,
        salt=salt,
        length=32
    )
    key = kdf.derive(password.encode('utf-8'))
    key = base64.urlsafe_b64encode(key)
    return key


def encrypt_with_aes(input_string, password, salt):
    key = generate_aes_key(password, salt)
    f = Fernet(key)
    encrypted_data = f.encrypt(input_string.encode('utf-8'))
    return encrypted_data    


def decrypt_with_aes(encrypted_data, password, salt):
    key = generate_aes_key(password, salt)
    f = Fernet(key)
    decrypted_data = f.decrypt(encrypted_data)
    return decrypted_data.decode('utf-8')


# Example values (safe defaults)
salt = b'salt1234'
password = "password123"
input_string = "test"

encrypted_value = encrypt_with_aes(input_string, password, salt)
decrypted_value = decrypt_with_aes(encrypted_value, password, salt)


# --- DNS RECORDS ---
dns_records = {
    'example.com.': {
        dns.rdatatype.A: '192.168.1.101',
        dns.rdatatype.AAAA: '2001:db8::1',
        dns.rdatatype.MX: [(10, 'mail.example.com.')],
        dns.rdatatype.SOA: (
            'ns1.example.com.',
            'admin.example.com.',
            2023081401,
            3600,
            1800,
            604800,
            86400,
        ),
    }
}


# --- DNS SERVER ---
def run_dns_server():
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    server_socket.bind(("127.0.0.1", 8053))  # safer than 53

    server_socket.settimeout(3)

    for _ in range(10):
        try:
            data, addr = server_socket.recvfrom(1024)

            request = dns.message.from_wire(data)
            response = dns.message.make_response(request)

            question = request.question[0]
            qname = question.name.to_text()
            qtype = question.rdtype

            if qname in dns_records and qtype in dns_records[qname]:
                answer_data = dns_records[qname][qtype]

                rdata_list = []

                if qtype == dns.rdatatype.MX:
                    for pref, server in answer_data:
                        rdata_list.append(MX(dns.rdataclass.IN, dns.rdatatype.MX, pref, server))

                elif qtype == dns.rdatatype.SOA:
                    mname, rname, serial, refresh, retry, expire, minimum = answer_data
                    rdata = SOA(
                        dns.rdataclass.IN,
                        dns.rdatatype.SOA,
                        mname,
                        rname,
                        serial,
                        refresh,
                        retry,
                        expire,
                        minimum
                    )
                    rdata_list.append(rdata)

                else:
                    rdata_list = [
                        dns.rdata.from_text(dns.rdataclass.IN, qtype, answer_data)
                    ]

                for rdata in rdata_list:
                    rrset = dns.rrset.RRset(question.name, dns.rdataclass.IN, qtype)
                    rrset.add(rdata)
                    response.answer.append(rrset)

            response.flags |= 1 << 10

            print("Responding to:", qname)

            server_socket.sendto(response.to_wire(), addr)

        except socket.timeout:
            break

    server_socket.close()


# --- RUNNER ---
def run_dns_server_user():
    print("DNS server is running...")

    def user_input():
        while True:
            cmd = input()
            if cmd.lower() == 'q':
                os.kill(os.getpid(), signal.SIGINT)

    threading.Thread(target=user_input, daemon=True).start()
    run_dns_server()


if __name__ == '__main__':
    run_dns_server_user()
