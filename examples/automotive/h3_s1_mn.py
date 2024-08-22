#!/usr/bin/python3
"""
This is an example how to simulate a client server environment.
"""
from mininet.net import Mininet
from mininet.node import Controller, RemoteController
from mininet.cli import CLI
from mininet.link import TCLink
from mininet.log import info, debug, setLogLevel
import pdb

setLogLevel('info')

def main():
    net = Mininet(controller=RemoteController, autoSetMacs=True, autoStaticArp=True)
    net.addController('c0', RemoteController, ip='10.0.0.10', port=6653)

    info('*** Setup network\n')
    h1 = net.addHost('h1', ip='10.0.0.1')
    h2 = net.addHost('h2', ip='10.0.0.2')
    h3 = net.addHost('h3', ip='10.0.0.3')
    s1 = net.addSwitch('s1')
    net.addLink(h1, s1)
    net.addLink(h2, s1)
    net.addLink(h3, s1)
    net.start()

    info('*** Starting to execute commands\n')

    # setting multicast IP for server
#ser_cmd = "route add -n 239.10.0.1 server-eth0"
#info(h1.cmd(ser_cmd) + "\n")

    # setting multicast IP for client
#cli_cmd = "route add -n 239.10.0.1 client-eth0"
#info(client.cmd(cli_cmd) + "\n")

    # setting basic OF rules to communicate between server and client
#    info(s1.cmd("ovs-ofctl -O OpenFlow13 add-flow s1 priority=1,in_port=s1-eth1,action=output:s1-eth2" + "\n"))
#    info(s1.cmd("ovs-ofctl -O OpenFlow13 add-flow s1 priority=1,in_port=s1-eth2,action=output:s1-eth1" + "\n"))

    CLI(net)
    net.stop()

if __name__ == "__main__":
    main()
