import threading
import dns.message
import dns.query
import time
import sys

root_list = ["198.41.0.4","199.9.14.201","192.33.4.12","199.7.91.13","192.203.230.10","192.5.5.241","192.112.36.4",
             "198.97.190.53","192.36.148.17","192.58.128.30","193.0.14.129","199.7.83.42","202.12.27.33"]


class My_Thread():
    # Initialize the class with domain name, dns query type and the dns server list.
    def __init__(self, domain_name, resolve_type, server_list):
        self.response = None
        self.domain_name = domain_name
        self.resolve_type = resolve_type
        self.server_list = server_list

    # Sending dns query and get the response.
    def dns_resolve(self, dns_server):
        try:
            dns_query = dns.message.make_query(self.domain_name, self.resolve_type)
            get_response = dns.query.udp(dns_query, dns_server, 53) # UDP is much faster than TCP but is easier to be hijacked.
            self.response = get_response
        except:
            pass

    # Process the response of dns server.
    def process_response(self):
        # Get three parts of dns response.
        result_answer = self.response.answer
        result_authority = self.response.authority
        result_additional = self.response.additional
        # If the "answer" part is not empty, there are two cases: further resolve domain name "CNAME" or directly return the answer.
        if result_answer != []:
            if len(result_answer) == 1 and result_answer[0].to_text().split()[3] == "CNAME":
                return My_Thread(result_answer[0].to_text().split()[4], self.resolve_type, self.server_list).main()
            else:
                return result_answer, len(self.response.to_wire())
        # Additional resolution using the additional part.
        else:
            # If the "additional" part is empty, get the IP address of dns servers using the "authority" part.
            if result_additional == []:
                if result_authority == []:
                    return []
                ns_list = []
                authority_text = result_authority[0].to_text().split()
                item_no = 4
                while item_no < len(authority_text):
                    ns_list.append(authority_text[item_no])
                    item_no = item_no + 5
                self.response = None
                item_no = 0
                while item_no > -1:
                    if self.response != None:
                        return self.process_response()
                    item_answer, _ = My_Thread(ns_list[item_no], "A", root_list).main()
                    ns_ip = item_answer[0].to_text().split()[4]
                    t = threading.Thread(target=self.dns_resolve, args=(ns_ip,))
                    t.daemon = True
                    t.start()
            # Get new dns server list from the "additional" part.
            next_server_list = []
            for item in result_additional:
                next_server_list.append(item.to_text().split()[4])
            return My_Thread(self.domain_name, self.resolve_type, next_server_list).main()

    def main(self):
        # Start multiple threads and each thread query one dns server in the list.
        for root_i in self.server_list:
            t = threading.Thread(target=self.dns_resolve, args=(root_i,))
            t.daemon = True
            t.start()
        while 1:
            # As long as one thread get the "response", further process the "response".
            if self.response != None:
                return self.process_response()

if __name__ == '__main__':
    target_domain_name = sys.argv[1]
    target_resolve_type = sys.argv[2]
    start_time = time.time()
    result_answer, result_MSG_size = My_Thread(target_domain_name, target_resolve_type, root_list).main()
    end_time = time.time()
    print("QUESTION SECTION: ")
    print(target_domain_name+'.', "IN ", target_resolve_type,"\n")
    print("ANSWER SECTION:")
    for i in result_answer:
        print(i.to_text())
    print("\nQuery time:", int((end_time-start_time)*1000), "msec")
    print("WHEN:", time.strftime('%a %b %d %H:%M:%S %Y',time.localtime(time.time())))
    print("MSG SIZE rcvd:", result_MSG_size)

