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

            generate_sha256_hash(qname)

            if qname not in dns_records:
                response.set_rcode(3)
            elif qtype not in dns_records[qname]:
                response.set_rcode(3)
            else:
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
                        qname, 300, dns.rdataclass.IN,
                        dns.rdatatype.to_text(qtype),
                        *answer_data
                    )
                    response.answer.append(rrset)

                else:
                    rrset = dns.rrset.from_text(
                        qname, 300, dns.rdataclass.IN,
                        dns.rdatatype.to_text(qtype),
                        answer_data
                    )
                    response.answer.append(rrset)

            server_socket.sendto(response.to_wire(), addr)

        except KeyboardInterrupt:
            server_socket.close()
            sys.exit(0)
