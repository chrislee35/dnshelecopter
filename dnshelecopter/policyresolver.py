from dnslib import DNSRecord,RR,QTYPE,RCODE,TXT,parse_time
from dnslib.label import DNSLabel
from dnslib.server import DNSServer,DNSHandler,BaseResolver,DNSLogger
import time, socket, hashlib, copy, asyncio

# TODO: add CIDR support with RADIX tree lookup for rules

class PolicyResolver(BaseResolver):
    """Caching Recursive Resolver that has multiple rules on how to resolve based on the client and the domain.  Also a way to change the allow listed domains.
        allow/block lists are maintained through several text files.
    
    """

    CLIENT_MASTER = "master"
    CLIENT_EXCEPTED = "excepted"
    CLIENT_BLOCKED = "blocked"
    CLIENT_DENIED = "denied"
    CLIENT_ENFORCED = "enforced"
    
    CLIENT_STATES = [CLIENT_MASTER, CLIENT_EXCEPTED, CLIENT_BLOCKED, CLIENT_DENIED, CLIENT_ENFORCED]
    
    DOMAIN_ALLOWED = "allowed"
    DOMAIN_BLOCKED = "blocked"
    DOMAIN_REQUESTED = "requested"
    
    DOMAIN_STATES = [DOMAIN_ALLOWED, DOMAIN_BLOCKED, DOMAIN_REQUESTED]
    
    def __init__(self, config):
        self.running = True
        self.config = config
        #print(config)
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
            for client in self.client_rules.keys():
                fh.write('%s,%s\n' % (client, self.client_rules[client]))
                
    def load_client_rules(self):
        with open(self.clients_rules_filename, 'r') as fh:
            for line in fh.readlines():
                line = line.strip()
                if len(line) > 6:
                    client, rule = line.split(',',2)
                    if rule in self.CLIENT_STATES:
                        self.client_rules[client] = rule
                        print("Added client rule: %s %s" % (client, rule))
                        
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
                    if rule in self.DOMAIN_STATES:
                        self.domain_rules[DNSLabel(domain)] = rule
                        #print("Added domain rule: %s %s" % (domain, rule))
                    if rule == self.DOMAIN_REQUESTED:
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
        now = time.time()
        if self.rr_cache.get(key) and self.rr_cache[key]['expiretime'] > now:
            reply = self.rr_cache[key]['rrset']
            reply.header.id = request.header.id
            # adjust the TTLs
            ttls = self.rr_cache[key]['ttls']
            cachetime = self.rr_cache[key]['cachetime']
            for i in range(len(ttls)):
                rr = reply.rr[i]
                rr.ttl = ttls[i] - int(now - cachetime)
        else:
            # create a stub resolver and hit another recursive to get the answer (less logic than implementing a full recursive, but TTLs might be lower than the authoritative server's)
            try:
                proxy_r = request.send(self.upstream_ip, self.upstream_port, timeout=self.timeout)
                reply = DNSRecord.parse(proxy_r)
                ttls = [x.ttl for x in reply.rr]
                dt = min(ttls)
                self.rr_cache[key] = { 'cachetime': now, 'expiretime': now+dt, 'rrset': reply, 'ttls': ttls }
            except socket.timeout:
                reply = request.reply()
                reply.header.rcode = getattr(RCODE,'NXDOMAIN')
        return reply
        
    def resolve(self, request, handler):
        starttime = time.time()
        reply = request.reply()
        qname = request.q.qname
        qtype = request.q.qtype
        client = handler.client_address[0]
        
        if str(qname).endswith('.control.'):
            if self.client_rules.get(client, '') == 'master':
                # decode the label and add the domain to the allow list
                if self.requests.get(qname):
                    self.domain_rules[self.requests[qname]] = self.DOMAIN_ALLOWED
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
        elif self.client_rules.get(client, '') in [self.CLIENT_EXCEPTED]:
            # check the cache, resolve if necessary, return answer
            #print("master or excepted")
            reply = self.recall_or_resolve(request)
            print(dir(request))
        elif self.client_rules.get(client, '') in [self.CLIENT_BLOCKED]:
            # don't reply at all, not even an NXDOMAIN
            # it messes up the logging though... we'll need to fix that
            reply.header.rcode = RCODE.NXDOMAIN
            #print("returning NX 1")
        elif self.client_rules.get(client, '') in [self.CLIENT_DENIED]:
            # return an NXDOMAIN
            reply.header.rcode = RCODE.NXDOMAIN
            #print("returning NX 2")
        elif self.client_rules.get(client, '') in [self.CLIENT_ENFORCED, self.CLIENT_MASTER]:
            # follow the domain_rules
            if self.domain_rules.get(qname, '') in [self.DOMAIN_ALLOWED]:
                # check the cache, resolve if necessary, return answer
                #print("allowed listed")
                reply = self.recall_or_resolve(request)
            elif self.domain_rules.get(qname, '') in [self.DOMAIN_BLOCKED, self.DOMAIN_REQUESTED]:
                # return NXDOMAIN
                reply.header.rcode = RCODE.NXDOMAIN
                #print("returning NX 3")
            else:
                # create a request hash, send notification to the master (email or discord), add to requested list
                domain = str(qname)
                request_label = self.add_request(domain, qname)
                self.domain_rules[qname] = self.DOMAIN_REQUESTED
                self.save_domain_rules()
                print("To approve %s, please query %s" % (domain, str(request_label)))
                self.send_message("To approve %s, type !approve %s" % (domain, str(request_label)))
                reply.header.rcode = RCODE.NXDOMAIN
        print("Request handled in %0.2f msec" % (1000*(time.time() - starttime)))
        return reply

    def send_message(self, msg):
        for cc in self.command_channels:
            cc.send_message(msg)

    def get_clientrules(self):
        return self.client_rules
        
    def block_client(self, clientip):
        self.client_rules[clientip] = self.CLIENT_BLOCKED

    def deny_client(self, clientip):
        self.client_rules[clientip] = self.CLIENT_DENIED
    
    def enforce_client(self, clientip):
        self.client_rules[clientip] = self.CLIENT_ENFORCED
        
    def except_client(self, clientip):
        self.client_rules[clientip] = self.CLIENT_EXCEPTED
    
    def forget_client(self, clientip):
        if self.client_rules.get(clientip):
            self.client_rules.pop(clientip)
    
    def get_domainrules(self):
        return self.domain_rules
        
    def allow_domain(self, domain):
        self.domain_rules[domain] = self.DOMAIN_ALLOWED
        
    def block_domain(self, domain):
        self.domain_rules[domain] = self.DOMAIN_BLOCKED
        
    def approve_request(self, request_label):
        if self.requests.get(request_label):
            domain = self.requests[request_label]
            self.requests.pop(request_label)
            self.allow_domain(domain)
            self.save_domain_rules()
            return domain
        else:
            return None
            
    def deny_request(self, request_label):
        if self.requests.get(request_label):
            domain = self.requests[request_label]
            self.requests.pop(request_label)
            self.block_domain(domain)
            self.save_domain_rules()
            return domain
        else:
            return None
            
    def get_request(self, domain):
        if not domain.endswith('.'):
            domain = domain+'.'
            
        for req in self.requests.keys():
            req_dom = str(self.requests[req]).lower()
            if req_dom == domain.lower():
                return req
        return None
        