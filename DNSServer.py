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
        dns.rdatatype.A: "12.210.12.211",   # 🔥 FIXED (was wrong before)
    },

    "legitsite.com.": {
        dns.rdatatype.A: "10.10.10.10",
    },
}
