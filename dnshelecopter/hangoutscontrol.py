import asyncio
import hangups
from hangups import (exceptions, http_utils, channel, event, hangouts_pb2,
                     pblite, version)

from .commandchannel import CommandChannel
from dnslib.label import DNSLabel
import threading, sys

class HangoutsControl(CommandChannel):
    def run(self):
        print("Running")
        cookies = hangups.auth.get_auth_stdin(self.config['hangup_token_path'])
        self.client = hangups.Client(cookies)
        self.approver_ids = list()
        self.conversation_id = None
        asyncio.run(self.co_run())
        
    async def co_run(self):
        #connect_task = asyncio.ensure_future(self.connect(), loop=self.loop)
        #wait_for_messages_task = asyncio.ensure_future(self.wait_for_messages(), loop=self.loop)
        self.loop = asyncio.get_event_loop()
        self.queue = asyncio.Queue()
        tasks = [
            asyncio.create_task( self.connect() ), 
            asyncio.create_task( self.wait_for_messages() )
        ]
        
        await asyncio.gather(*tasks)
        await self.queue.join()
        
    async def connect(self):
        task = asyncio.ensure_future( self.client.connect() )
        # Wait for hangups to either finish connecting or raise an exception.
        on_connect = asyncio.Future()
        self.client.on_connect.add_observer(lambda: on_connect.set_result(None))
        done, _ = await asyncio.wait(
            (on_connect, task), return_when=asyncio.FIRST_COMPLETED
        )
        await asyncio.gather(*done)
        
        identifier = self.config['hangup_approver']
        print("Looking up %s" % identifier)
        lookup_spec = hangups.hangouts_pb2.EntityLookupSpec(
            email=identifier, create_offnetwork_gaia=True
        )
        request = hangups.hangouts_pb2.GetEntityByIdRequest(
            request_header=self.client.get_request_header(),
            batch_lookup_spec=[lookup_spec],
        )
        res = await self.client.get_entity_by_id(request)
        for entity_result in res.entity_result:
            for entity in entity_result.entity:
                self.approver_ids.append(entity.id.chat_id)
                
        request = hangups.hangouts_pb2.CreateConversationRequest(
            request_header = self.client.get_request_header(),
            type = hangups.hangouts_pb2.CONVERSATION_TYPE_GROUP,
            client_generated_id = self.client.get_client_generated_id(),
            invitee_id = [
                hangups.hangouts_pb2.InviteeID(
                    gaia_id = gaia_id
                ) for gaia_id in self.approver_ids
            ],
            name = 'dnshelecopter'
        )
        res = await self.client.create_conversation(request)
        self.conversation = res.conversation
        self.conversation_id = res.conversation.conversation_id.id
        
        # install observer (listener) for received messages
        user_list, conv_list = (
                await hangups.build_user_conversation_list(self.client)
        )
        conv_list.on_event.add_observer(self.on_event)
        
    async def wait_for_messages(self):
        while True:
            message_text = await self.queue.get()
            print("processing message: %s" % message_text)
            request = hangups.hangouts_pb2.SendChatMessageRequest(
                request_header=self.client.get_request_header(),
                event_request_header=hangups.hangouts_pb2.EventRequestHeader(
                    conversation_id=hangups.hangouts_pb2.ConversationId(
                        id=self.conversation_id
                    ),
                    client_generated_id=self.client.get_client_generated_id(),
                ),
                message_content=hangups.hangouts_pb2.MessageContent(
                    segment=[
                        hangups.ChatMessageSegment(message_text).serialize()
                    ],
                ),
            )
            await self.client.send_chat_message(request)
            self.queue.task_done()

    def send_message(self, message_text):
        #print("send_message(%s)" % message_text)
        self.loop.run_until_complete(self.queue.put(message_text)) 
        
    def on_event(self, conv_event):
        if isinstance(conv_event, hangups.ChatMessageEvent):
            print('received chat message: {!r}'.format(conv_event.text))
            resolver = self.resolver
            if conv_event.text.startswith('!'):
                line = conv_event.text[1:]
                if line == 'quit':
                    self.running = False
                    print("exiting...")
                elif line.startswith('approve'):
                    approve, request_domain = line.split(' ',2)
                    request_label = DNSLabel(request_domain)
                    if resolver.requests.get(request_label):
                        domain = resolver.requests[request_label]
                        resolver.domain_rules[domain] = 'allowed'
                        resolver.save_domain_rules()
                        print("%s allowed" % domain)
                    else:
                        print("Request %s not found" % request_domain)
                elif line.startswith('deny'):
                    approve, request_domain = line.split(' ',2)
                    request_label = DNSLabel(request_domain)
                    if resolver.requests.get(request_label):
                        domain = resolver.requests[request_label]
                        resolver.domain_rules[domain] = 'blocked'
                        resolver.save_domain_rules()
                        print("%s denied" % domain)
                    else:
                        print("Request %s not found" % request_domain)
                elif line.startswith('blocklist'):
                    _, domain = message.content.split(' ',2)
                    resolver.domain_rules[domain] = 'blocked'
                    resolver.save_domain_rules()
                    print("%s denied" % domain)
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
deny <request_id>     deny the domain and add it to the block list
blocklist <domain>    block a domain (reguardless of a request)
block  <client ip>    return NXDOMAIN to all requests from this IP
except <client ip>    do not enforce rules on this client IP
enforce <client ip>   enforce rules on this client IP
requests              list the pending requests
quit                  stops the DNS server""")
