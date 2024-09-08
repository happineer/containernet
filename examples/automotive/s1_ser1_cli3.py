#!/usr/bin/python3
"""
This is an example how to simulate a client server environment.
"""
from mininet.net import Containernet
from mininet.node import Controller, RemoteController
from mininet.cli import CLI
from mininet.link import TCLink, Link
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

    server = net.addDocker(f"server", dimage="v2architect/someip:v00.02",
                                 ip=f"10.0.0.1", mac=f"00:00:00:00:00:01",
                                 cpuset_cpus="0",
                                 mem_limit=1073741824,  # 1G
                                 #cpu_shares=20,
                                 volumes=vols,
                                 Privileged=True,
                                 environment=option_env)

    clients = []
    n_client = 3
    for n in range(2, n_client+2):
        clients.append(net.addDocker(f"client{n}", dimage="v2architect/someip:v00.02",
                                     ip=f"10.0.0.{n}", mac=f"00:00:00:00:00:0{n}",
                                     cpuset_cpus=f"{n}",
                                     mem_limit=1073741824,  # 1G
                                     #cpu_shares=20,
                                     volumes=vols,
                                     Privileged=True,
                                     environment=option_env))

    info('*** Setup network\n')
    s1 = net.addSwitch('s1')
    net.addLink(server, s1, cls=TCLink, bw=100, delay='1ms')
    for cl in clients:
        net.addLink(cl, s1, cls=TCLink, bw=100, delay='1ms')
    net.start()

    info('*** Starting to execute commands\n')

    # setting multicast IP for server
    ser_cmd = f"route add -n 239.10.0.1 server-eth0"
    info(server.cmd(ser_cmd) + "\n")

    ser_cmd = f"route add -n 239.10.0.2 server-eth0"
    info(server.cmd(ser_cmd) + "\n")

    cli_cmd = f"route add -n 224.0.0.107 server-eth0"
    info(server.cmd(cli_cmd) + "\n")

    cli_cmd = f"route add -n 224.0.1.129 server-eth0"
    info(server.cmd(cli_cmd) + "\n")

    cli_cmd = f"route add -n 224.0.0.22 server-eth0"
    info(server.cmd(cli_cmd) + "\n")


    # setting multicast IP for client
    for n, client in enumerate(clients, 2):
        cli_cmd = f"route add -n 239.10.0.1 client{n}-eth0"
        info(client.cmd(cli_cmd) + "\n")

        cli_cmd = f"route add -n 239.10.0.2 client{n}-eth0"
        info(client.cmd(cli_cmd) + "\n")

        cli_cmd = f"route add -n 224.0.0.107 client{n}-eth0"
        info(client.cmd(cli_cmd) + "\n")

        cli_cmd = f"route add -n 224.0.1.129 client{n}-eth0"
        info(client.cmd(cli_cmd) + "\n")

        cli_cmd = f"route add -n 224.0.0.22 client{n}-eth0"
        info(client.cmd(cli_cmd) + "\n")


    info(s1.cmd('ovs-ofctl -O OpenFlow13 add-flow s1 "priority=0,actions=NORMAL"' + '\n'))


    '''
    info(s1.cmd("ovs-ofctl -O OpenFlow13 add-flow s1 ip,nw_dst=10.0.0.1,action=output:s1-eth1" + "\n"))
    info(s1.cmd("ovs-ofctl -O OpenFlow13 add-flow s1 ip,nw_dst=10.0.0.2,action=output:s1-eth2" + "\n"))
    info(s1.cmd("ovs-ofctl -O OpenFlow13 add-flow s1 ip,nw_dst=10.0.0.3,action=output:s1-eth3" + "\n"))
    info(s1.cmd("ovs-ofctl -O OpenFlow13 add-flow s1 ip,nw_dst=10.0.0.4,action=output:s1-eth4" + "\n"))

    multicast_ip = ['239.10.0.1', '239.10.0.2', '224.0.0.107', '224.0.1.129', '224.0.0.22']
    for multi_ip in multicast_ip:
        info(s1.cmd(f"ovs-ofctl -O OpenFlow13 add-flow s1 ip,in_port=s1-eth1,nw_dst={multi_ip},action=flood" + "\n"))
        info(s1.cmd(f"ovs-ofctl -O OpenFlow13 add-flow s1 ip,in_port=s1-eth2,nw_dst={multi_ip},action=flood" + "\n"))
        info(s1.cmd(f"ovs-ofctl -O OpenFlow13 add-flow s1 ip,in_port=s1-eth3,nw_dst={multi_ip},action=flood" + "\n"))
        info(s1.cmd(f"ovs-ofctl -O OpenFlow13 add-flow s1 ip,in_port=s1-eth4,nw_dst={multi_ip},action=flood" + "\n"))
    '''



    '''
    info(s1.cmd('ovs-ofctl -O OpenFlow13 add-flow s1 "ip,in_port=s1-eth1,actions=normal"' + '\n'))
    info(s1.cmd('ovs-ofctl -O OpenFlow13 add-flow s1 "ip,in_port=s1-eth2,actions=normal"' + '\n'))
    info(s1.cmd('ovs-ofctl -O OpenFlow13 add-flow s1 "ip,in_port=s1-eth3,actions=normal"' + '\n'))
    info(s1.cmd('ovs-ofctl -O OpenFlow13 add-flow s1 "ip,in_port=s1-eth4,actions=normal"' + '\n'))
    '''

    """
    # setting basic OF rules to communicate between server and client
    info(s1.cmd("ovs-ofctl -O OpenFlow13 add-flow s1 priority=1,in_port=s1-eth1,action=output:s1-eth2" + "\n"))
    info(s1.cmd("ovs-ofctl -O OpenFlow13 add-flow s1 priority=1,in_port=s1-eth2,action=output:s1-eth1" + "\n"))
    """

    '''
    # SOME/IP-SD packet forwarding
    info(s1.cmd("ovs-ofctl -O OpenFlow13 add-flow s1 ip,in_port=s1-eth1,nw_dst=239.10.0.1,action=flood" + "\n"))
    info(s1.cmd("ovs-ofctl -O OpenFlow13 add-flow s1 ip,in_port=s1-eth2,nw_dst=239.10.0.1,action=flood" + "\n"))
    info(s1.cmd("ovs-ofctl -O OpenFlow13 add-flow s1 ip,in_port=s1-eth3,nw_dst=239.10.0.1,action=flood" + "\n"))
    info(s1.cmd("ovs-ofctl -O OpenFlow13 add-flow s1 ip,in_port=s1-eth4,nw_dst=239.10.0.1,action=flood" + "\n"))

    info(s1.cmd("ovs-ofctl -O OpenFlow13 add-flow s1 ip,in_port=s1-eth1,nw_dst=239.10.0.2,action=flood" + "\n"))
    info(s1.cmd("ovs-ofctl -O OpenFlow13 add-flow s1 ip,in_port=s1-eth2,nw_dst=239.10.0.2,action=flood" + "\n"))
    info(s1.cmd("ovs-ofctl -O OpenFlow13 add-flow s1 ip,in_port=s1-eth3,nw_dst=239.10.0.2,action=flood" + "\n"))
    info(s1.cmd("ovs-ofctl -O OpenFlow13 add-flow s1 ip,in_port=s1-eth4,nw_dst=239.10.0.2,action=flood" + "\n"))
    #info(s1.cmd("ovs-ofctl -O OpenFlow13 add-flow s1 ip,in_port=s1-eth1,nw_dst=239.10.0.2,action=output:s1-eth2" + "\n"))
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
    info(s1.cmd("ovs-ofctl -O OpenFlow13 add-flow s1 ip,nw_dst=10.0.0.4,action=output:s1-eth4" + "\n"))
    #info(s1.cmd("ovs-ofctl -O OpenFlow13 add-flow s1 ip,in_port=s1-eth1,nw_dst=10.0.0.2,action=output:s1-eth2" + "\n"))
    #info(s1.cmd("ovs-ofctl -O OpenFlow13 add-flow s1 ip,in_port=s1-eth2,nw_dst=10.0.0.1,action=output:s1-eth1" + "\n"))
    '''

    CLI(net)
    net.stop()

if __name__ == "__main__":
    main()
