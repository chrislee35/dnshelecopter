# dnshelecopter
Website policy-enforcing system via DNS - When new sites are visited, the manager can allow it.

# Installation

For now, you'll need to clone from github and install:

    git clone https://github.com/chrislee35/dnshelecopter.git
    cd dnshelecopter
    pip3 install -r requirements.txt
    python3 setup.py install

# Configuration

The tool right now only uses Discord as a command channel.  That will update soon, but for now, you'll need a bot and your user id.  Update the dnshelecopter.conf file with those values.  You'll also want to update the other values as needed.

    [dnshelecopter]
    server_bind_ip=127.0.0.1
    server_bind_port=5354
    clients_rules_filename=config/clients.conf
    domains_rules_filename=config/domains.conf
    secret_hashkey=fedcba9876543210
    command_channels=discord
    upstream_recursive_dns_ip=192.168.1.1
    upstream_recursive_dns_port=53

    [discord]
    discord_bot_token=INSERT_TOKEN_HERE
    discord_approver=INSERT_DISCORD_APPROVER_HERE

# How this works

This opens a UDP socket on the given port and listens for DNS requests.  It then evaluates the source (by IP) and the domain to determine whether to resolve or not.  If the source is "enforced" and the domain isn't expressly allowed or blocked, then it will return a NXDOMAIN, but will send a notification to the command channel asking for express approval or rejection of the domain.