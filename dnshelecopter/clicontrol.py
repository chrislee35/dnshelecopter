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
            if line.startswith('requests'):
                msg = ""
                for req in resolver.requests.keys():
                    msg += "%s: %s\n" % (str(resolver.requests[req]), req)
                print(msg)
            elif line.startswith('request allow '):
                _, _, request_domain = line.split(' ',3)
                request_label = DNSLabel(request_domain)
                domain = resolver.approve_request(request_domain)
                if domain:
                    print("%s allowed" % domain)
                else:
                    print("Request %s not found" % request_domain)
            elif line.startswith('request deny '):
                _, _, request_domain = line.split(' ',2)
                request_label = DNSLabel(request_domain)
                domain = resolver.deny_request(request_domain)
                if domain:
                    print("%s blocked" % domain)
                else:
                    print("Request %s not found" % request_domain)
            elif line.startswith('domains'):
                rules = resolver.get_domainrules()
                col1width = max([ len(x) for x in rules.keys() ]) + 1
                if col1width < 5:
                    col1width = 5
                print("%s Rule" % 'Domain'.ljust(col1width))
                print("%s ==========" % ('='*col1width))
                filt = None
                lineparts = line.split(' ')
                if len(lineparts) > 1:
                    filt = lineparts[1]
                for dom in sorted(rules.keys(), key=str):
                    if filt and not filt in str(dom):
                        continue
                    print('%s %s' % (str(dom).ljust(col1width), rules[dom]))
            elif line.startswith('domain block'):
                _, _, domain = line.split(' ',3)
                req = resolver.get_request(domain)
                if req:
                    resolver.deny_request(req)
                else:
                    resolver.block_domain(domain)
                resolver.save_domain_rules()
                print("%s denied" % domain)
            elif line.startswith('domain allow'):
                _, _, domain = line.split(' ',3)
                req = resolver.get_request(domain)
                if req:
                    resolver.approve_request(req)
                else:
                    resolver.allow_domain(domain)
                resolver.save_domain_rules()
                print("%s allowed" % domain)
            elif line.startswith('clients'):
                print("Client             Rule")
                print("================== ================")
                filt = None
                lineparts = line.split(' ')
                if len(lineparts) > 1:
                    filt = lineparts[1]
                for client in sorted(resolver.get_clientrules().keys()):
                    if filt and not filt in client:
                        continue
                    else:
                        print('%s %s' % (client.rjust(18), resolver.client_rules[client]))
            elif line.startswith('client block'):
                _, _, clientip = line.split(' ', 3)
                resolver.block_client(clientip)
                resolver.save_client_rules()
            elif line.startswith('client enforce'):
                _, _, clientip = line.split(' ', 3)
                resolver.enforce_client(clientip)
                resolver.save_client_rules()
            elif line.startswith('client except'):
                _, _, clientip = line.split(' ', 3)
                resolver.except_client(clientip)
                resolver.save_client_rules()
            elif line.startswith('client deny'):
                _, _, clientip = line.split(' ', 3)
                resolver.deny_client(clientip)
                resolver.save_client_rules()
            elif line == 'help':
                print("""-= Requests =-
requests                      list all requests
request approve <request_id>  approve the request tied to a domain, (hash.control.)
request deny <request_id>     deny the domain and add it to the block list

-= Domains =-
domains [filter]              list all domain rules
domain allow <domain>         allow a domain
domain block <domain>         block a domain

-= Clients =-
clients [filter]              list all client rules
client block <ip>             do not reply at all to this IP
client except <ip>            resolve everytime for this IP, regardless of rules
client enforce <ip>           enforce the rules on this client
client deny <ip>              return NXDOMAIN to all requests from this IP

-= Other =-
quit                          stops the DNS server
help                          this useful stuff""")
                
            elif line == 'quit':
                self.running = False
                self.resolver.running = False
                print("exiting...")
            else:
                print("unknown command")
