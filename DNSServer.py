import dns.message
import dns.rdatatype
import dns.rdataclass
import dns.rdata
import dns.rrset
import socket
import sys
import hashlib
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import base64


def generate_aes_key(password, salt):
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        iterations=100000,
        salt=salt,
        length=32
    )
    key = kdf.derive(password.encode("utf-8"))
    return base64.urlsafe_b64encode(key)


def encrypt_with_aes(input_string, password, salt):
    key = generate_aes_key(password, salt)
    f = Fernet(key)
    return f.encrypt(input_string.encode("utf-8"))


def decrypt_with_aes(encrypted_data, password, salt):
    key = generate_aes_key(password, salt)
    f = Fernet(key)
    return f.decrypt(encrypted_data).decode("utf-8")


salt = b"salt1234"
password = "password123"
input_string = "test"

encrypted_value = encrypt_with_aes(input_string, password, salt)
decrypted_value = decrypt_with_aes(encrypted_value, password, salt)


def generate_sha256_hash(input_string):
    sha256_hash = hashlib.sha256()
    sha256_hash.update(input_string.encode("utf-8"))
    return sha256_hash.hexdigest()


dns_records = {
    "example.com.": {
        dns.rdatatype.A: "192.168.1.101",
        dns.rdatatype.AAAA: "2001:0db8:85a3:0000:0000:8a2e:0370:7334",
        dns.rdatatype.MX: [(10, "mail.example.com.")],
        dns.rdatatype.CNAME: "www.example.com.",
        dns.rdatatype.NS: "ns.example.com.",
        dns.rdatatype.TXT: ("This is a TXT record",),
        dns.rdatatype.SOA: (
            "ns1.example.com.",
            "admin.example.com.",
            2023081401,
            3600,
            1800,
            604800,
            86400,
        ),
    },
    "nyu.edu.": {
        dns.rdatatype.A: "216.165.61.24",
        dns.rdatatype.AAAA: "2620:12a:8000::1",
        dns.rdatatype.MX: [(10, "mxa-00256a01.gslb.pphosted.com.")],
        dns.rdatatype.NS: "ns1.nyu.edu.",
    },
    "google.com.": {
        dns.rdatatype.A: "111.111.111.111",
    },
    "yahoo.com.": {
        dns.rdatatype.A: "98.137.246.7",
    },
    "safebank.com.": {
        dns.rdatatype.A: "12.210.12.210",
    },
    "legitsite.com.": {
        dns.rdatatype.A: "10.10.10.10",
    },
}


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

            if qname in dns_records and qtype in dns_records[qname]:
                answer_data = dns_records[qname][qtype]

                if qtype == dns.rdatatype.MX:
                    rrset = dns.rrset.from_text(
                        qname, 300, dns.rdataclass.IN, "MX",
                        *[f"{pref} {host}" for pref, host in answer_data]
                    )
                    response.answer.append(rrset)

                elif qtype == dns.rdatatype.SOA:
                    mname, rname, serial, refresh, retry, expire, minimum = answer_data
                    rrset = dns.rrset.from_text(
                        qname, 300, dns.rdataclass.IN, "SOA",
                        f"{mname} {rname} {serial} {refresh} {retry} {expire} {minimum}"
                    )
                    response.answer.append(rrset)

                elif isinstance(answer_data, tuple):
                    rrset = dns.rrset.from_text(
                        qname, 300, dns.rdataclass.IN, dns.rdatatype.to_text(qtype), *answer_data
                    )
                    response.answer.append(rrset)

                else:
                    rrset = dns.rrset.from_text(
                        qname, 300, dns.rdataclass.IN, dns.rdatatype.to_text(qtype), answer_data
                    )
                    response.answer.append(rrset)
            else:
                response.set_rcode(3)

            server_socket.sendto(response.to_wire(), addr)

        except KeyboardInterrupt:
            server_socket.close()
            sys.exit(0)


if __name__ == "__main__":
    run_dns_server()
