import dns.name
import dns.query
import sys
import time
import threading
import dns.message

root_list = ["198.41.0.4", "199.9.14.201", "192.33.4.12", "199.7.91.13", "192.203.230", "192.5.5.241", "192.112.36.4",
             "198.97.190.53", "192.36.148.17", "192.58.128.30", "193.0.14.129", "199.7.83.42", "202.12.27.33"]

root_key = ["257 3 8 AwEAAagAIKlVZrpC6Ia7gEzahOR+9W29 euxhJhVVLOyQbSEW0O8gcCjFFVQUTf6v 58fLjwBd0YI0EzrAcQqBGCzh/RStIoO8 g0NfnfL2MTJRkxoXbfDaUeVPQuYEhg37 NZWAJQ9VnMVDxP/VHL496M/QZxkjf5/E fucp2gaDX6RS6CXpoY68LsvPVjR0ZSwz z1apAzvN9dlzEheX7ICJBBtuA6G3LQpz W5hOA2hzCTMjJPJ8LbqF6dsV6DoBQzgu l0sGIcGOYl7OyQdXfZ57relSQageu+ip AdTTJ25AsRTAoub8ONGcLmqrAmRLKBP1 dfwhYB4N7knNnulqQxA+Uk1ihz0=",
    "257 3 8 AwEAAaz/tAm8yTn4Mfeh5eyI96WSVexT BAvkMgJzkKTOiW1vkIbzxeF3+/4RgWOq 7HrxRixHlFlExOLAJr5emLvN7SWXgnLh 4+B5xQlNVz8Og8kvArMtNROxVQuCaSnI DdD5LKyWbRd2n9WGe2R8PzgCmr3EgVLr jyBxWezF0jLHwVN8efS3rCj/EWgvIWgb 9tarpVUDK/b58Da+sqqls3eNbuv7pr+e oZG+SrDK6nWeL3c6H5Apxz7LjVc1uTId sIXxuOLYA4/ilBmSVIzuDWfdRUfhHdY6 +cn8HFRm+2hM8AnXGXws9555KrUB5qih ylGa8subX2Nn6UwNR1AkUTV74bU="]

class My_Thread():
    def __init__(self, domain_name, server_list, pre_DS):
        self.response_A = None
        self.response_DNSKEY = None
        self.domain_name = domain_name
        self.server_list = server_list
        self.pre_DS = pre_DS
        self.dns_support = True
        self.dns_validation = True

    def validate_root(self, root_i):
        dns_query = dns.message.make_query('.', dns.rdatatype.DNSKEY, want_dnssec=True)
        response_DNSKEY = dns.query.tcp(dns_query, root_i, 53)
        name = dns.name.from_text('.')
        if len(response_DNSKEY.answer) == 2:
            try:
                dns.dnssec.validate(response_DNSKEY.answer[0], response_DNSKEY.answer[1],
                                    {name: response_DNSKEY.answer[0]})
            except dns.dnssec.ValidationFailure:
                self.dns_validation = False
            else:
                pass
            ksk_list = response_DNSKEY.answer[0].to_text().split()
            flag = False
            for item in ksk_list:
                if item in root_key[0] or item in root_key[1]:
                    flag = True
            self.dns_validation = flag
        else:
            self.dns_support = False

    def dns_resolve(self, dns_server):
        if dns_server in root_list:
            try:
                validate_root(dns_server)
            except:
                self.dns_support = False
        try:
            dns_query = dns.message.make_query(self.domain_name, dns.rdatatype.A, want_dnssec=True)
            get_response = dns.query.tcp(dns_query, dns_server, 53)
            self.response_A = get_response
            dns_query = dns.message.make_query(self.domain_name, dns.rdatatype.DNSKEY, want_dnssec=True)
            get_response = dns.query.tcp(dns_query, dns_server, 53)
            self.response_DNSKEY = get_response
        except:
            pass

    def process_response(self):
        result_answer_A = self.response_A.answer
        result_authority_A = self.response_A.authority
        result_additional_A = self.response_A.additional
        result_answer_DNSKEY = self.response_DNSKEY.answer
        result_authority_DNSKEY = self.response_DNSKEY.authority

        # Validate KSK by previous DS record
        if self.server_list != root_list:
            if len(result_answer_DNSKEY) == 2:
                cur_name = result_answer_DNSKEY[0].to_text().split()[0]
                flag = False
                for item in result_answer_DNSKEY[0]:
                    cur_DS = dns.dnssec.make_ds(name=cur_name, key=item, algorithm='SHA256').to_text().split()[-1]
                    cur_DS_1 = dns.dnssec.make_ds(name=cur_name, key=item, algorithm='SHA1').to_text().split()[-1]
                    if cur_DS == self.pre_DS or cur_DS_1 == self.pre_DS:
                        flag = True
                        break
                    else:
                        continue
                self.dns_validation = flag
            if len(result_authority_DNSKEY) == 3:
                cur_name = result_authority_DNSKEY[0].to_text().split()[0]
                flag = False
                for item in result_authority_DNSKEY[1]:
                    cur_DS = dns.dnssec.make_ds(name=cur_name, key=item, algorithm='SHA256').to_text().split()[-1]
                    cur_DS_1 = dns.dnssec.make_ds(name=cur_name, key=item, algorithm='SHA1').to_text().split()[-1]
                    if cur_DS == self.pre_DS or cur_DS_1 == self.pre_DS:
                        flag = True
                        break
                    else:
                        continue
                self.dns_validation = flag

        # Update DS record
        if len(result_authority_DNSKEY) > 1:
            self.pre_DS = result_authority_DNSKEY[1].to_text().split()[-1]

        # Validate RRST and RRSIG
        if len(result_answer_A) == 2 and len(result_answer_DNSKEY) > 1:
            name = dns.name.from_text(result_answer_A[0].to_text().split()[0])
            try:
                dns.dnssec.validate(result_answer_A[0], result_answer_A[1], {name: result_answer_DNSKEY[0]})
            except dns.dnssec.ValidationFailure:
                self.dns_validation = False
            else:
                pass
        if len(result_answer_A) == 1:
            self.dns_support = False

            # Validate DS and RRSIG DS
        if result_answer_A == []:
            if len(result_authority_A) == 3 and len(result_answer_DNSKEY) > 0:
                name = dns.name.from_text(result_authority_A[0].to_text().split()[0])
                try:
                    dns.dnssec.validate(result_authority_A[1], result_authority_A[2], {name: result_answer_DNSKEY[0]})
                except dns.dnssec.ValidationFailure:
                    self.dns_validation = False
                else:
                    pass
            else:
                self.dns_support = False

        # Validate DNSKEY and RRSSIG DNSKEY
        if len(result_answer_DNSKEY) == 2:
            name = dns.name.from_text(result_answer_DNSKEY[0].to_text().split()[0])
            try:
                dns.dnssec.validate(result_answer_DNSKEY[0], result_answer_DNSKEY[1], {name: result_answer_DNSKEY[0]})
            except dns.dnssec.ValidationFailure:
                self.dns_validation = False
            else:
                pass
        elif result_authority_DNSKEY == []:
            self.dns_support = False

        if result_answer_A != []:
            if len(result_answer_A) == 1 and result_answer_A[0].to_text().split()[3] == "CNAME":
                return My_Thread(result_answer_A[0].to_text().split()[4], self.server_list, self.pre_DS).main()
            else:
                return result_answer_A, len(self.response_A.to_wire()) + len(
                    self.response_DNSKEY.to_wire()), self.dns_validation, self.dns_support
        else:
            if result_additional_A == []:
                if result_authority_A == []:
                    return []
                ns_list = []
                authority_text = result_authority_A[0].to_text().split()
                item_no = 4
                while item_no < len(authority_text):
                    ns_list.append(authority_text[item_no])
                    item_no = item_no + 5
                self.response_A = None
                self.response_DNSKEY = None
                item_no = 0
                while item_no > -1:
                    if self.response_A != None and self.response_DNSKEY != None:
                        return self.process_response()
                    item_answer, _, _, _ = My_Thread(ns_list[item_no], root_list, self.pre_DS).main()
                    ns_ip = item_answer[0].to_text().split()[4]
                    t = threading.Thread(target=self.dns_resolve, args=(ns_ip,))
                    t.daemon = True
                    t.start()
            next_server_list = []
            for item in result_additional_A:
                next_server_list.append(item.to_text().split()[4])
            return My_Thread(self.domain_name, next_server_list, self.pre_DS).main()

    def main(self):
        for root_i in self.server_list:
            t = threading.Thread(target=self.dns_resolve, args=(root_i,))
            t.daemon = True
            t.start()
        while 1:
            if self.response_A != None and self.response_DNSKEY != None:
                return self.process_response()


if __name__ == '__main__':
    target_domain_name = sys.argv[1]
    start_time = time.time()
    result_answer, result_MSG_size, result_validation, result_support = My_Thread(target_domain_name, root_list, "").main()
    end_time = time.time()
    if result_validation == False:
        print("DNSSEC verification failed\n")
    elif result_support == False:
        print("DNSSEC not supported\n")
    else:
        print("DNSSEC configured and verification succeeded\n")
    print("QUESTION SECTION: ")
    print(target_domain_name+'.', "A ","\n")
    print("ANSWER SECTION:")
    print(result_answer[0])
    print("\nQuery time:", int((end_time-start_time)*1000), "msec")
    print("WHEN:", time.strftime('%a %b %d %H:%M:%S %Y',time.localtime(time.time())))
    print("MSG SIZE rcvd:", result_MSG_size)

