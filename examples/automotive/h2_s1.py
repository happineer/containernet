#!/usr/bin/python3
"""
This is an example how to simulate a client server environment.
"""
from mininet.net import Containernet
from mininet.node import Controller, RemoteController
from mininet.cli import CLI
from mininet.link import TCLink
from mininet.log import info, debug, setLogLevel
import pdb

setLogLevel('info')

def main():
    net = Containernet(controller=RemoteController)
    net.addController('c0', RemoteController, ip='192.168.56.10', port=6653)

    info('*** Adding server and client container\n')

    option_env = { 
        "LD_LIBRARY_PATH": "/root/someip/libs:/usr/local/lib"
    }   

    vols = [ 
        "/lib/modules:/lib/modules",
        "/usr/src:/usr/src",
        "/usr/lib/python3:/usr/lib/python3",
        "/usr/local/lib/python3.8:/usr/local/lib/python3.8",
        "/usr/lib/x86_64-linux-gnu:/usr/lib/x86_64-linux-gnu",
        "/usr/bin:/usr/bin",
        "/sys/kernel/debug:/sys/kernel/debug"
    ]

    server = net.addDocker('server', dimage="v2architect/someip:v00.01",
                                     ip='10.0.0.101', mac="00:00:00:00:01:01",
#volumes=vols,
                                     Privileged=True,
                                     environment=option_env)

    client = net.addDocker('client', dimage="v2architect/someip:v00.01",
                                     ip='10.0.0.102', mac="00:00:00:00:01:02",
#volumes=vols,
                                     Privileged=True,
                                     environment=option_env)

    info('*** Setup network\n')
    s1 = net.addSwitch('s1')
    net.addLink(server, s1)
    net.addLink(client, s1)
    net.start()

    info('*** Starting to execute commands\n')

    # setting multicast IP for server
    ser_cmd = "route add -n 239.10.0.1 server-eth0"
    info(server.cmd(ser_cmd) + "\n")

    # setting multicast IP for client
    cli_cmd = "route add -n 239.10.0.1 client-eth0"
    info(client.cmd(cli_cmd) + "\n")

    # setting basic OF rules to communicate between server and client
    info(s1.cmd("ovs-ofctl -O OpenFlow13 add-flow s1 priority=1,in_port=s1-eth1,action=output:s1-eth2" + "\n"))
    info(s1.cmd("ovs-ofctl -O OpenFlow13 add-flow s1 priority=1,in_port=s1-eth2,action=output:s1-eth1" + "\n"))

    CLI(net)
    net.stop()

if __name__ == "__main__":
    main()
