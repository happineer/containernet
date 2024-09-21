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
import time

setLogLevel('info')

node_conf = {
    "zone_gw_fl": { "ip": "10.0.0.1/16", "mac": "00:00:00:00:00:01" },
    "zone_gw_fr": { "ip": "10.0.0.2/16", "mac": "00:00:00:00:00:02" },
    "zone_gw_rl": { "ip": "10.0.0.3/16", "mac": "00:00:00:00:00:03" },
    "zone_gw_rr": { "ip": "10.0.0.4/16", "mac": "00:00:00:00:00:04" },
    "ivi":        { "ip": "10.0.0.5/16", "mac": "00:00:00:00:00:05" },
    "cluster":    { "ip": "10.0.0.6/16", "mac": "00:00:00:00:00:06" },
    "adas":       { "ip": "10.0.0.7/16", "mac": "00:00:00:00:00:07" },
    "telematics": { "ip": "10.0.0.8/16", "mac": "00:00:00:00:00:08" },
}

# DON'T ADD host's (/tmp) -> impact to the behavior of vsomeip
vols = [ 
    "/bin:/bin",
    "/etc:/etc",
    "/lib:/lib",
    "/lib32:/lib32",
    "/lib64:/lib64",
    "/libx32:/libx32",
    "/opt:/opt",
    "/sbin:/sbin",
    "/sys:/sys",
    "/usr:/usr",
    "/var:/var",
    "/home/jhshin/work/someip_app/tmp:/tmp/uds",
    "/home/jhshin/work/someip_app:/root/someip_app"
]

option_env = { 
    "LD_LIBRARY_PATH": "/root/someip/libs:/usr/local/lib"
}   

def create_node(net, name, cpu, mem, dimage="v2architect/someip:v00.02"):
    global vols
    ip_addr = node_conf[name]["ip"]
    mac_addr = node_conf[name]["mac"]
    node = net.addDocker(name, dimage=dimage,
                         ip=ip_addr, mac=mac_addr,
                         cpuset_cpus=cpu,
                         mem_limit=mem,
                         Privileged=True,
                         volumes=vols,
                         environment=option_env)
    return node


def main():
    net = Containernet(controller=RemoteController, autoStaticArp=True)

    info('*** Zonal E/E Architecture based In-Vehicle network ***\n')
    info('*** Central Switch(1), Zonal Gateway(4), IVI, Cluster, ADAS, Telematics ***\n')

    c_sw = net.addSwitch('s1')

    '''
    zone_gw_fl = create_node(net, "zone_gw_fl", cpu="0",     mem=1 * 1024 * 1024 * 1024)
    zone_gw_fr = create_node(net, "zone_gw_fr", cpu="1",     mem=1 * 1024 * 1024 * 1024)
    zone_gw_rl = create_node(net, "zone_gw_rl", cpu="2",     mem=1 * 1024 * 1024 * 1024)
    zone_gw_rr = create_node(net, "zone_gw_rr", cpu="3",     mem=1 * 1024 * 1024 * 1024)
    ivi        = create_node(net, "ivi",        cpu="4,5",   mem=4 * 1024 * 1024 * 1024)
    cluster    = create_node(net, "cluster",    cpu="6",     mem=1 * 1024 * 1024 * 1024)
    adas       = create_node(net, "adas",       cpu="7,8",   mem=4 * 1024 * 1024 * 1024)
    telematics = create_node(net, "telematics", cpu="9",     mem=1 * 1024 * 1024 * 1024)

    vECUs = [
        zone_gw_fl, zone_gw_fr, zone_gw_rl, zone_gw_rr,
        ivi,        cluster,    adas,       telematics
    ]
    '''

    # debug
    info('*** Setup In-vehicle network\n')
    #adas       = create_node(net, "adas",       cpu="7,8",   mem=4 * 1024 * 1024 * 1024)
    ivi        = create_node(net, "ivi",        cpu="4,5",   mem=4 * 1024 * 1024 * 1024)
    telematics = create_node(net, "telematics", cpu="9",     mem=1 * 1024 * 1024 * 1024)
    vECUs = [telematics, ivi]

    for vECU in vECUs:
        #net.addLink(vECU, c_sw, cls=TCLink, bw=100, delay='1ms')
        net.addLink(vECU, c_sw, cls=Link, bw=100)
    net.start()

    info('*** Starting to execute commands\n')
    multicast_ip_list = [
        "239.10.0.1",   # SOME/IP service discovery (239.10.0.1-5)
        "239.10.0.11",
        "239.10.0.12",
        "239.10.0.13",
        "239.10.0.14",
        "239.10.0.15",
        #"224.0.0.107",  # PTP?
        #"224.0.1.129",  # PTP?
        #"224.0.0.22"    # IGMP
    ]

    for vECU in vECUs:
        info(f"[{vECU.name}] multicast route setting\n")
        for m_ip in multicast_ip_list:
            route_setup_cmd = f"route add -n {m_ip} {vECU.name}-eth0"
            vECU.cmd(route_setup_cmd)

            #vECU.cmd(f'ip link set {vECU.name}-eth0 txqueuelen 0')
            #vECU.cmd(f'ip link set {vECU.name}-eth0 txqueuelen 0')
            #sudo ifconfig telematics-eth0 broadcast 10.0.255.255

            #time.sleep(0.5)
            #vECU.cmd("route add -net 224.0.0.0 netmask 255.255.255.0 dev {vECU.name}-eth0")
            #vECU.cmd("route add -net 224.0.1.0 netmask 255.255.255.0 dev {vECU.name}-eth0")

    info(f"OVS actions=NORMAL rule setting\n")
    c_sw.cmd('ovs-ofctl add-flow s1 "dl_type=0x0800,nw_proto=2,actions=drop"')
    c_sw.cmd('ovs-ofctl add-flow s1 "dl_dst=01:00:5e:00:01:81,actions=NORMAL"')
    c_sw.cmd('ovs-vsctl set Bridge s1 mcast_snooping_enable=true')
    c_sw.cmd('ovs-ofctl -O OpenFlow13 add-flow s1 "priority=0,actions=NORMAL"')

    # run background process
    # - SOME/IP routingmanager daemon)
    # - PTP daemon (NOT WORKING...)
    for vECU in vECUs:
        #debug
        continue

        if vECU.name != 'telematics':
            info(f"[{vECU.name}] run routing managerd\n")
            vECU.cmd('/root/someip_app/services/routingmanager/run_routingd.sh &')
        time.sleep(1)


    info(f"[Telematics] add vlan 1\n")
    telematics.cmd(f'/root/someip_app/utils/add_vlan.sh 1')

    # run PTP daemon
    info(f"[Telematics] run PTP master\n")
    info(f'/usr/sbin/ptp4l -f /etc/linuxptp/ptp4l.conf -i veth0.1 -S & \n')
    telematics.cmd(f'/usr/sbin/ptp4l -f /etc/linuxptp/ptp4l.conf -i veth0.1 -S &')
    time.sleep(1)


    vECU_dict = {vECU.name: vECU for vECU in vECUs}
    # SOME/IP Service
    service_node = {
        "SteeringWheel": {
            "server": "zone_gw_fl",
            "clients": ["adas"]
        },
        "TrafficLight": {
            "server": "telematics",
            "clients": ["adas"]
        },
        "Intersection": {
            "server": "telematics",
            "clients": ["adas"]
        },
        "ObjectDetection": {
            "server": "adas",
            "clients": ["ivi"]
        },
        "VehicleSpeed": {
            "server": "zone_gw_rr",
            "clients": ["cluster", "ivi", "adas"]
        },
        "VehiclePose": {
            "server": "zone_gw_rl",
            "clients": ["adas"]
        },
        "VehicleAccel": {
            "server": "zone_gw_fr",
            "clients": ["adas"]
        },
        "VehicleLocation": {
            "server": "telematics",
            "clients": ["ivi", "cluster"]
        },
        "Transmission": {
            "server": "zone_gw_fl",
            "clients": ["adas", "ivi", "cluster"]
        },
        "Driving": {
            "server": "zone_gw_fr",
            "clients": ["adas"]
        },
        "Collision": {
            "server": "adas",
            "clients": ["ivi", "cluster"]
        }
    }

    # Server/Client SOME/IP service start
    for service, node_info in service_node.items():
        # debug
        continue

        server, clients = node_info['server'], node_info['clients']

        run_server_cmd = f'/root/someip_app/services/{service}/run_server.sh udp 2 &'
        info(f"[{server}] {run_server_cmd}\n")
        vECU_dict[server].cmd(run_server_cmd)
        time.sleep(2)

        for client in clients:
            run_client_cmd = f'/root/someip_app/services/{service}/run_client.sh udp 2 &'
            info(f"[{client}] {run_client_cmd}\n")
            vECU_dict[client].cmd(run_client_cmd)
            time.sleep(2)


    CLI(net)
    net.stop()

if __name__ == "__main__":
    main()
