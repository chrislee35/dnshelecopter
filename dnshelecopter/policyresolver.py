from dnslib import DNSRecord,RR,QTYPE,RCODE,TXT,parse_time
from dnslib.label import DNSLabel
from dnslib.server import DNSServer,DNSHandler,BaseResolver,DNSLogger
import time, socket, hashlib, copy, asyncio

class PolicyResolver(BaseResolver):
    """Caching Recursive Resolver that has multiple rules on how to resolve based on the client and the domain.  Also a way to change the allow listed domains.
        allow/block lists are maintained through several text files.
    
    """

    def __init__(self, config):
        self.config = config
        print(config)
        self.upstream_ip = config['upstream_recursive_dns_ip']
        self.upstream_port = int(config['upstream_recursive_dns_port'])
        self.secret_hashkey = config['secret_hashkey']
        self.clients_rules_filename = config['clients_rules_filename']
        self.domains_rules_filename = config['domains_rules_filename']

        self.origin = DNSLabel("control")
        self.timeout = int(config.get('timeout', 10))
        
        self.command_channels = []
        self.client_rules = {}
        self.domain_rules = {}
        self.rr_cache = {}
        self.requests = {}
        self.rrs = RR.fromZone(". 60 IN A 127.0.0.1")
        
        self.load_client_rules()
        self.load_domain_rules()
        
    def add_command_channel(self, command_channel):
        self.command_channels.append(command_channel)
        
    def remove_command_channel(self, command_channel):
        self.command_channels.remove(command_channel)
        
    def save_client_rules(self):
        with open(self.clients_rules_filename, 'w') as fh:
            for dom in self.domain_rules.keys():
                fh.write('%s,%s\n' % (str(dom), self.domain_rules[dom]))
                
    def load_client_rules(self):
        with open(self.clients_rules_filename, 'r') as fh:
            for line in fh.readlines():
                line = line.strip()
                if len(line) > 6:
                    client, rule = line.split(',',2)
                    if rule in ['master','excepted','blocked','denied','enforced']:
                        self.client_rules[client] = rule
                        #print("Added client rule: %s %s" % (client, rule))
                        
    def save_domain_rules(self):
        with open(self.domains_rules_filename, 'w') as fh:
            for domain in self.domain_rules.keys():
                fh.write('%s,%s\n' % (domain, self.domain_rules[domain]))
    
    def load_domain_rules(self):
        with open(self.domains_rules_filename, 'r') as fh:
            for line in fh.readlines():
                line = line.strip()
                if len(line) > 6:
                    domain, rule = line.split(',',2)
                    if rule in ['allowed', 'blocked', 'requested']:
                        self.domain_rules[DNSLabel(domain)] = rule
                        #print("Added domain rule: %s %s" % (domain, rule))
                    if rule == 'requested':
                        request_label = self.add_request(domain, DNSLabel(domain))
                        print("To approve %s, please query %s" % (domain, str(request_label)))

    def add_request(self, domain, qname):
        request_hash = hashlib.md5((self.secret_hashkey+domain).encode('utf-8')).hexdigest()
        request_label = DNSLabel([request_hash.encode('UTF-8'), b'control'])
        self.requests[request_label] = qname
        return request_label

    def recall_or_resolve(self, request):
        qname = request.q.qname
        key = QTYPE[request.q.qtype]+':'+str(qname)
        if self.rr_cache.get(key) and self.rr_cache[key]['lifetime'] > time.time():
            # TODO: adjust the TTLs
            reply = self.rr_cache[key]['rrset']
            reply.header.id = request.header.id
        else:
            # create a stub resolver and hit another recursive to get the answer (less logic than implementing a full recursive, but TTLs might be lower than the authoritative server's)
            try:
                proxy_r = request.send(self.upstream_ip, self.upstream_port, timeout=self.timeout)
                reply = DNSRecord.parse(proxy_r)
                self.rr_cache[key] = { 'lifetime': time.time() + 120, 'rrset': reply }
            except socket.timeout:
                reply = request.reply()
                reply.header.rcode = getattr(RCODE,'NXDOMAIN')
        return reply
        
        
    def resolve(self, request, handler):
        reply = request.reply()
        qname = request.q.qname
        qtype = request.q.qtype
        client = handler.client_address[0]
        
        if str(qname).endswith('.control.'):
            if self.client_rules.get(client, '') == 'master':
                # decode the label and add the domain to the allow list
                if self.requests.get(qname):
                    self.domain_rules[self.requests[qname]] = 'allowed'
                    self.save_domain_rules()
                    for rr in self.rrs:
                        a = copy.copy(rr)
                        a.rname = qname
                        reply.add_answer(a)
                else:
                    print("tried to allow something that hasn't been requested")
                    reply.header.rcode = RCODE.NXDOMAIN
            else:
                print("unauthenticated")
                reply.header.rcode = RCODE.NXDOMAIN
        elif self.client_rules.get(client, '') in ['excepted']:
            # check the cache, resolve if necessary, return answer
            print("master or excepted")
            reply = self.recall_or_resolve(request)
            print(dir(request))
        elif self.client_rules.get(client, '') in ['blocked']:
            # don't reply at all, not even an NXDOMAIN
            # it messes up the logging though... we'll need to fix that
            reply.header.rcode = RCODE.NXDOMAIN
            print("returning NX 1")
            
        elif self.client_rules.get(client, '') in ['denied']:
            # return an NXDOMAIN
            reply.header.rcode = RCODE.NXDOMAIN
            print("returning NX 2")
        elif self.client_rules.get(client, '') in ['enforced', 'master']:
            # follow the domain_rules
            if self.domain_rules.get(qname, '') in ['allowed']:
                # check the cache, resolve if necessary, return answer
                print("allowed listed")
                reply = self.recall_or_resolve(request)
            elif self.domain_rules.get(qname, '') in ['blocked', 'requested']:
                # return NXDOMAIN
                reply.header.rcode = RCODE.NXDOMAIN
                print("returning NX 3")
            else:
                # create a request hash, send notification to the master (email or discord), add to requested list
                domain = str(qname)
                request_label = self.add_request(domain, qname)
                self.domain_rules[qname] = 'requested'
                self.save_domain_rules()
                print("To approve %s, please query %s" % (domain, str(request_label)))
                self.send_message("To approve %s, type !approve %s" % (domain, str(request_label)))
                reply.header.rcode = RCODE.NXDOMAIN
        return reply

    def send_message(self, msg):
        for cc in self.command_channels:
            cc.send_message(msg)

