class CommandChannel(object):
    def __init__(self, config, resolver):
        self.config = config
        self.resolver = resolver
        
    def send_message(self, msg):
        print(msg)
        
    def run(self):
        raise Exception("Not implemented")
