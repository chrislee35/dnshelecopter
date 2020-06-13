import hashlib, time
from aiohttp import web
from dnslib.label import DNSLabel
from .commandchannel import CommandChannel

class HTTPControl(CommandChannel):
    def __init__(self, config, resolver):
        self.config = config
        self.resolver = resolver
        app = web.Application()
        self.app = app
        app.add_routes([
            web.get("/token", self.token),
            web.post("/login", self.login),
            web.get("/clients", self.clients),
            web.get("/domains", self.domains),
            web.post("/client", self.set_client),
            web.post("/domain", self.set_domain),
            web.static('/', "html/")
        ])
        print("HTTPControl app")
        
    async def token(self, request):
        # generate a random token and remember it for a little while
        self.token = hashlib.sha256(str(time.time()).encode('UTF-8')).hexdigest()
        return web.json_response({'token': self.token})
        
    async def login(self, request):
        data = await request.post()
        match = hashlib.sha256((self.token+self.config['password']).encode("UTF-8")).hexdigest()
        # generate a random token and remember it for a little while
        if data['credential'] == match:
            return web.json_response({'status': 'OK'})
        else:
            return web.json_response({'status': 'FAILED', 'error': 'bad password '+match+" "+self.token+self.config['password']})
        
    async def clients(self, request):
        return web.json_response(self.resolver.client_rules)

    async def domains(self, request):
        domain_rules = {}
        for dr in self.resolver.domain_rules.keys():
            domain_rules[str(dr)] = self.resolver.domain_rules[dr]
        return web.json_response(domain_rules)
        
    async def set_client(self, request):
        data = await request.post()
        if data.get('ip') and data.get('status') and data['status'] in ['master','excepted','blacklisted','denied','enforced']:
            self.resolver.client_rules[data['ip']] = data['status']
            return web.json_response({'status': 'OK', 'message': 'client %s set to %s' % (data['ip'], data['status'])})
        else:
            return web.json_response({'status': 'FAILURE', 'error': 'could not understand request'})

    async def set_domain(self, request):
        data = await request.post()
        if data.get('domain') and data.get('status') and data['status'] in ['whitelisted', 'blacklisted', 'requested']:
            self.resolver.domain_rules[DNSLabel(data['domain'])] = data['status']
            return web.json_response({'status': 'OK', 'message': 'domain %s set to %s' % (data['domain'], data['status'])})
        else:
            return web.json_response({'status': 'FAILURE', 'error': 'could not understand request'})
        
    def run(self):
        print("running HTTPControl")
        web.run_app(self.app)
