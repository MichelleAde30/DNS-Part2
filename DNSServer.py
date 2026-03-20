import dns.message
import dns.name
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

    def is_exfiltration(self, qname):
        """
        Detect possible DNS exfiltration attempts.
        This blocks domains with many labels or unusually long labels.
        """
        qname_str = str(qname).lower()

        labels = [label for label in qname_str.strip(".").split(".") if label]

        # Too many subdomains is suspicious
        if len(labels) > 4:
            return True

        # Very long full query is suspicious
        if len(qname_str) > 50:
            return True

        # Very long label is suspicious
        for label in labels:
            if len(label) > 15:
                return True

        return False

    def handle_query(self, request_bytes):
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

        # Exfiltration detection for Part 2
        if self.is_exfiltration(qname):
            print(f"Potential DNS exfiltration detected: {qname_str}")
            reply.set_rcode(dns.rcode.NXDOMAIN)
            return reply.to_wire()

        if qname_str not in self.dns_records:
            print(f"{qname_str} not found.")
            reply.set_rcode(dns.rcode.NXDOMAIN)
            return reply.to_wire()

        records = self.dns_records[qname_str]

        if qtype not in records:
            print(f"{qname_str} has no record for requested type.")
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

        elif qtype == dns.rdatatype.TXT:
            for txt in record_value:
                rrset = dns.rrset.from_text(qname_str, 300, "IN", "TXT", f'"{txt}"')
                reply.answer.append(rrset)

        elif qtype == dns.rdatatype.SOA:
            mname, rname, serial, refresh, retry, expire, minimum = record_value
            rrset = dns.rrset.from_text(
                qname_str,
                300,
                "IN",
                "SOA",
                f"{mname} {rname} {serial} {refresh} {retry} {expire} {minimum}",
            )
            reply.answer.append(rrset)

        print(f"{qname_str} resolves!")
        return reply.to_wire()
