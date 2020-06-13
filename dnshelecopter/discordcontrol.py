import discord, asyncio, threading, hashlib, time
from dnslib.label import DNSLabel
from .commandchannel import CommandChannel

class DiscordControl(CommandChannel):
    def __init__(self, config, resolver):
        self.config = config
        self.resolver = resolver
        
        self.discord_approver_user_id = int(config['discord_approver'])
        self.discord_bot_token = self.config['discord_bot_token']
        
        client = discord.Client()
        self.client = client

        @client.event
        async def on_message(message):
            # we do not want the bot to reply to itself
            if message.author == client.user:
                return

            if message.content.startswith('!quit'):
                await client.logout()
                await client.close()
            elif message.content.startswith('!approve'):
                approve, request_domain = message.content.split(' ',2)
                request_label = DNSLabel(request_domain)
                if resolver.requests.get(request_label):
                    domain = resolver.requests[request_label]
                    resolver.domain_rules[domain] = 'whitelisted'
                    resolver.save_domain_rules()
                    await message.channel.send("%s whitelisted" % domain)
                else:
                    await message.channel.send("Request %s not found" % request_domain)
            elif message.content.startswith('!deny'):
                approve, request_domain = message.content.split(' ',2)
                request_label = DNSLabel(request_domain)
                if resolver.requests.get(request_label):
                    domain = resolver.requests[request_label]
                    resolver.domain_rules[domain] = 'blacklisted'
                    resolver.save_domain_rules()
                    await message.channel.send("%s blacklisted" % domain)
                else:
                    await message.channel.send("Request %s not found" % request_domain)
            elif message.content.startswith('!blacklist'):
                _, domain = message.content.split(' ',2)
                resolver.domain_rules[domain] = 'blacklisted'
                resolver.save_domain_rules()
                await message.channel.send("%s blacklisted" % domain)
            elif message.content.startswith('!block'):
                _, clientip = message.content.split(' ', 2)
                resolver.client_rules[client] = 'denied'
                resolver.save_client_rules()
            elif message.content.startswith('!enforce'):
                _, clientip = message.content.split(' ', 2)
                resolver.client_rules[client] = 'enforced'
                resolver.save_client_rules()
            elif message.content.startswith('!except'):
                _, clientip = message.content.split(' ', 2)
                resolver.client_rules[client] = 'excepted'
                resolver.save_client_rules()
            elif  message.content.startswith('!requests'):
                msg = ""
                for req in resolver.requests.keys():
                    msg += "%s: %s\n" % (str(resolver.requests[req]), req)
                await message.channel.send(msg)
            elif message.content == '!help':
                await message.channel.send("""
!help                  this useful stuff
!approve <request_id>  approve the request tied to a domain, (hash.control.)
!deny <request_id>     deny the domain and add it to the blacklist
!blacklist <domain>    blacklist a domain (reguardless of a request)
!block  <client ip>    return NXDOMAIN to all requests from this IP
!except <client ip>    do not enforce rules on this client IP
!enforce <client ip>   enforce rules on this client IP
!requests              list the pending requests
!quit                  stops the DNS server""")

        @client.event
        async def on_ready():
            print('Logged in as')
            print(client.user.name)
            print(client.user.id)
            print('------')
            
    def send_message(self, msg):
        master = self.client.get_user(self.discord_approver_user_id)
        coro = master.send(msg)
        fut = asyncio.run_coroutine_threadsafe(coro, self.client.loop)
        try:
            fut.result()
        except:
            # an error happened sending the message
            pass
    
    def run(self):
        self.thread = threading.Thread(target=self.start)
        self.thread.start()
       
    def start(self):
        self.client.run(self.discord_bot_token)
        
