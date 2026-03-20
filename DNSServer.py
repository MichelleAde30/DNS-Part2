from cryptography.fernet import Fernet
import dns.message
import dns.rdatatype
import dns.rrset
import dns.rcode


dns_records = {
    "example.com.": {
        dns.rdatatype.A: "192.168.1.101",
        dns.rdatatype.AAAA: "2001:0db8:85a3:0000:0000:8a2e:0370:7334",
        dns.rdatatype.MX: [(10, "mail.example.com.")],
        dns.rdatatype.CNAME: "www.example.com.",
        dns.rdatatype.NS: "ns.example.com.",
    },
    "nyu.edu.": {
        dns.rdatatype.A: "216.165.47.10",
        dns.rdatatype.AAAA: "2001:db8:85a3::8a2e:373:7312",
        dns.rdatatype.MX: [(10, "mxa-00256a01.gslb.pphosted.com.")],
        dns.rdatatype.NS: "ns1.nyu.edu.",
    },
    "safebank.com.": {
        dns.rdatatype.A: "10.10.10.10",
    },
}


class DNSServer:
    def __init__(self):
        self.dns_records = dns_records

        # keep one key for the whole server instance
        self.key = Fernet.generate_key()
        self.cipher = Fernet(self.key)

        # store tokens consistently as strings
        self.user_tokens = {}

    def store_token(self, user_email, domain):
        """
        Encrypt and store the domain safely.
        Fernet returns bytes, so decode once for storage.
        """
        token = self.cipher.encrypt(domain.encode("utf-8"))
        self.user_tokens[user_email] = token.decode("utf-8")

    def read_token(self, user_email):
        """
        Read token back and convert to bytes before decrypting.
        """
        if user_email not in self.user_tokens:
            return None

        token_str = self.user_tokens[user_email]
        token_bytes = token_str.encode("utf-8")
        decrypted = self.cipher.decrypt(token_bytes)
        return decrypted.decode("utf-8")

    def handle_query(self, request_bytes, user_email=None):
        request = dns.message.from_wire(request_bytes)
        reply = dns.message.make_response(request)

        if len(request.question) == 0:
            reply.set_rcode(dns.rcode.FORMERR)
            return reply.to_wire()

        question = request.question[0]
        qname = question.name
        qtype = question.rdtype
        qname_str = str(qname)

        print(f"Responding to request: {qname_str}")

        # Part 2 token storage / recovery check
        if user_email is not None:
            print(f"User Email: {user_email}")
            try:
                self.store_token(user_email, qname_str)
                recovered_domain = self.read_token(user_email)

                if recovered_domain != qname_str:
                    print("Something is wrong with how you are storing the token")
                    reply.set_rcode(dns.rcode.SERVFAIL)
                    return reply.to_wire()

            except Exception as e:
                print(f"decrypt error! Type: {type(e)} Value: {e}")
                print("Something is wrong with how you are storing the token")
                reply.set_rcode(dns.rcode.SERVFAIL)
                return reply.to_wire()

        if qname_str not in self.dns_records:
            reply.set_rcode(dns.rcode.NXDOMAIN)
            return reply.to_wire()

        records = self.dns_records[qname_str]

        if qtype not in records:
            reply.set_rcode(dns.rcode.NXDOMAIN)
            return reply.to_wire()

        record_value = records[qtype]

        if qtype == dns.rdatatype.A:
            rrset = dns.rrset.from_text(qname_str, 300, "IN", "A", record_value)
            reply.answer.append(rrset)

        elif qtype == dns.rdatatype.AAAA:
            rrset = dns.rrset.from_text(qname_str, 300, "IN", "AAAA", record_value)
            reply.answer.append(rrset)

        elif qtype == dns.rdatatype.NS:
            rrset = dns.rrset.from_text(qname_str, 300, "IN", "NS", record_value)
            reply.answer.append(rrset)

        elif qtype == dns.rdatatype.CNAME:
            rrset = dns.rrset.from_text(qname_str, 300, "IN", "CNAME", record_value)
            reply.answer.append(rrset)

        elif qtype == dns.rdatatype.MX:
            for preference, exchange in record_value:
                rrset = dns.rrset.from_text(
                    qname_str, 300, "IN", "MX", f"{preference} {exchange}"
                )
                reply.answer.append(rrset)

        print(f"{qname_str} resolves!")
        return reply.to_wire()
