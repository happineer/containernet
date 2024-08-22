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
    net = Containernet(controller=RemoteController, autoStaticArp=True)
    #net.addController('c0', RemoteController, ip='192.168.56.10', port=6653)

    info('*** Adding server and client container\n')

    option_env = { 
        "LD_LIBRARY_PATH": "/root/someip/libs:/usr/local/lib"
    }   

    """
        "/usr/src:/usr/src",
        "/usr/lib/python3:/usr/lib/python3",
        "/usr/local/lib/python3.8:/usr/local/lib/python3.8",
        "/usr/lib/x86_64-linux-gnu:/usr/lib/x86_64-linux-gnu",
        "/usr/bin:/usr/bin",
        "/usr/sbin:/usr/sbin",
        "/lib/modules:/lib/modules",
        "/etc/alternatives:/etc/alternatives",
        "/sys/kernel/debug:/sys/kernel/debug",
    """
    vols = [ 
        "/bin:/bin",
        "/usr:/usr",
        "/lib:/lib",
        "/lib32:/lib32",
        "/lib64:/lib64",
        "/etc:/etc",
        "/sys:/sys",
        "/home/jhshin/work/someip_app:/root/someip_app"
    ]

    servers = []
    n_server = 3

    pdb.set_trace()

    for n in range(1, n_server+1):
        servers.append(net.addDocker(f"server{n}", dimage="v2architect/someip:v00.01",
                                     ip=f"10.0.0.{n}", mac=f"00:00:00:00:00:0{n}",
                                     #cpu_shares=20,
                                     #cpuset_cpus="0",
                                     #mem_limit=1073741824,  # 1G
                                     volumes=vols,
                                     Privileged=True,
                                     environment=option_env))

    client = net.addDocker('client', dimage="v2architect/someip:v00.01",
                                     ip='10.0.0.10', mac="00:00:00:00:00:10",
                                     #cpu_shares=80,
                                     #cpuset_cpus="0",
                                     #mem_limit=1073741824,  # 1G
                                     volumes=vols,
                                     Privileged=True,
                                     environment=option_env)

    info('*** Setup network\n')
    s1 = net.addSwitch('s1')
    for server in servers:
        net.addLink(server, s1)
    net.addLink(client, s1)
    net.start()

    info('*** Starting to execute commands\n')

    # setting multicast IP for server
    for n, server in enumerate(servers, 1):
        ser_cmd = f"route add -n 239.10.0.1 server{n}-eth0"
        info(server.cmd(ser_cmd) + "\n")

    # setting multicast IP for client
    cli_cmd = "route add -n 239.10.0.1 client-eth0"
    info(client.cmd(cli_cmd) + "\n")

    """
    # setting basic OF rules to communicate between server and client
    info(s1.cmd("ovs-ofctl -O OpenFlow13 add-flow s1 priority=1,in_port=s1-eth1,action=output:s1-eth2" + "\n"))
    info(s1.cmd("ovs-ofctl -O OpenFlow13 add-flow s1 priority=1,in_port=s1-eth2,action=output:s1-eth1" + "\n"))
    """

    # SOME/IP-SD packet forwarding
    info(s1.cmd("ovs-ofctl -O OpenFlow13 add-flow s1 ip,in_port=s1-eth1,nw_dst=239.10.0.1,action=flood" + "\n"))
    info(s1.cmd("ovs-ofctl -O OpenFlow13 add-flow s1 ip,in_port=s1-eth2,nw_dst=239.10.0.1,action=flood" + "\n"))
    info(s1.cmd("ovs-ofctl -O OpenFlow13 add-flow s1 ip,in_port=s1-eth3,nw_dst=239.10.0.1,action=flood" + "\n"))
    info(s1.cmd("ovs-ofctl -O OpenFlow13 add-flow s1 ip,in_port=s1-eth4,nw_dst=239.10.0.1,action=flood" + "\n"))
    #info(s1.cmd("ovs-ofctl -O OpenFlow13 add-flow s1 ip,in_port=s1-eth1,nw_dst=239.10.0.1,action=output:s1-eth2" + "\n"))
    #info(s1.cmd("ovs-ofctl -O OpenFlow13 add-flow s1 ip,in_port=s1-eth2,nw_dst=239.10.0.1,action=output:s1-eth1" + "\n"))

    # IGMP packet forwarding
    info(s1.cmd("ovs-ofctl -O OpenFlow13 add-flow s1 ip,in_port=s1-eth1,nw_dst=224.0.0.22,action=flood" + "\n"))
    info(s1.cmd("ovs-ofctl -O OpenFlow13 add-flow s1 ip,in_port=s1-eth2,nw_dst=224.0.0.22,action=flood" + "\n"))
    info(s1.cmd("ovs-ofctl -O OpenFlow13 add-flow s1 ip,in_port=s1-eth3,nw_dst=224.0.0.22,action=flood" + "\n"))
    info(s1.cmd("ovs-ofctl -O OpenFlow13 add-flow s1 ip,in_port=s1-eth4,nw_dst=224.0.0.22,action=flood" + "\n"))
    #info(s1.cmd("ovs-ofctl -O OpenFlow13 add-flow s1 ip,in_port=s1-eth1,nw_dst=224.0.0.22,action=output:s1-eth2" + "\n"))
    #info(s1.cmd("ovs-ofctl -O OpenFlow13 add-flow s1 ip,in_port=s1-eth2,nw_dst=224.0.0.22,action=output:s1-eth1" + "\n"))

    # SOME/IP-SD packet forwarding
    info(s1.cmd("ovs-ofctl -O OpenFlow13 add-flow s1 ip,nw_dst=10.0.0.1,action=output:s1-eth1" + "\n"))
    info(s1.cmd("ovs-ofctl -O OpenFlow13 add-flow s1 ip,nw_dst=10.0.0.2,action=output:s1-eth2" + "\n"))
    info(s1.cmd("ovs-ofctl -O OpenFlow13 add-flow s1 ip,nw_dst=10.0.0.3,action=output:s1-eth3" + "\n"))
    info(s1.cmd("ovs-ofctl -O OpenFlow13 add-flow s1 ip,nw_dst=10.0.0.10,action=output:s1-eth4" + "\n"))
    #info(s1.cmd("ovs-ofctl -O OpenFlow13 add-flow s1 ip,in_port=s1-eth1,nw_dst=10.0.0.2,action=output:s1-eth2" + "\n"))
    #info(s1.cmd("ovs-ofctl -O OpenFlow13 add-flow s1 ip,in_port=s1-eth2,nw_dst=10.0.0.1,action=output:s1-eth1" + "\n"))

    CLI(net)
    net.stop()

if __name__ == "__main__":
    main()
