from .commandchannel import CommandChannel
from dnslib.label import DNSLabel
import threading, sys

class CLIControl(CommandChannel):
    def run(self):
        print("Running")
        self.running = True
        self.thread = threading.Thread( target = self.prompt )
        self.thread.start()
        
    def prompt(self):
        resolver = self.resolver
        while self.running:
            sys.stdout.write('> ')
            sys.stdout.flush()
            line = sys.stdin.readline().strip()
            if line == 'quit':
                self.running = False
                print("exiting...")
            elif line.startswith('approve'):
                approve, request_domain = line.split(' ',2)
                request_label = DNSLabel(request_domain)
                if resolver.requests.get(request_label):
                    domain = resolver.requests[request_label]
                    resolver.domain_rules[domain] = 'whitelisted'
                    resolver.save_domain_rules()
                    print("%s whitelisted" % domain)
                else:
                    print("Request %s not found" % request_domain)
            elif line.startswith('deny'):
                approve, request_domain = line.split(' ',2)
                request_label = DNSLabel(request_domain)
                if resolver.requests.get(request_label):
                    domain = resolver.requests[request_label]
                    resolver.domain_rules[domain] = 'blacklisted'
                    resolver.save_domain_rules()
                    print("%s blacklisted" % domain)
                else:
                    print("Request %s not found" % request_domain)
            elif line.startswith('blacklist'):
                _, domain = message.content.split(' ',2)
                resolver.domain_rules[domain] = 'blacklisted'
                resolver.save_domain_rules()
                print("%s blacklisted" % domain)
            elif line.startswith('block'):
                _, clientip = line.split(' ', 2)
                resolver.client_rules[client] = 'denied'
                resolver.save_client_rules()
            elif line.startswith('enforce'):
                _, clientip = line.split(' ', 2)
                resolver.client_rules[client] = 'enforced'
                resolver.save_client_rules()
            elif line.startswith('except'):
                _, clientip = line.split(' ', 2)
                resolver.client_rules[client] = 'excepted'
                resolver.save_client_rules()
            elif line.startswith('requests'):
                msg = ""
                for req in resolver.requests.keys():
                    msg += "%s: %s\n" % (str(resolver.requests[req]), req)
                print(msg)
            elif line == 'help':
                print("""help                  this useful stuff
approve <request_id>  approve the request tied to a domain, (hash.control.)
deny <request_id>     deny the domain and add it to the blacklist
blacklist <domain>    blacklist a domain (reguardless of a request)
block  <client ip>    return NXDOMAIN to all requests from this IP
except <client ip>    do not enforce rules on this client IP
enforce <client ip>   enforce rules on this client IP
requests              list the pending requests
quit                  stops the DNS server""")
