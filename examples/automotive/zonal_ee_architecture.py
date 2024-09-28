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
import os

setLogLevel('info')

node_conf = {
    "zone_gw_fl": { "ip": "10.0.0.1/24", "mac": "00:00:00:00:00:01", "id": 1},
    "zone_gw_fr": { "ip": "10.0.0.2/24", "mac": "00:00:00:00:00:02", "id": 2},
    "zone_gw_rl": { "ip": "10.0.0.3/24", "mac": "00:00:00:00:00:03", "id": 3},
    "zone_gw_rr": { "ip": "10.0.0.4/24", "mac": "00:00:00:00:00:04", "id": 4},
    "ivi":        { "ip": "10.0.0.5/24", "mac": "00:00:00:00:00:05", "id": 5},
    "cluster":    { "ip": "10.0.0.6/24", "mac": "00:00:00:00:00:06", "id": 6},
    "adas":       { "ip": "10.0.0.7/24", "mac": "00:00:00:00:00:07", "id": 7},
    "telematics": { "ip": "10.0.0.8/24", "mac": "00:00:00:00:00:08", "id": 8},
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
    "LD_LIBRARY_PATH": "/root/someip/libs:/usr/local/lib",
    "PATH": "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/root/someip_app/scripts"
}   
def calc_elapsed_time(name, time_s, time_e):
    elapsed_time = time_e - time_s
    print("")
    print(f"=" * 60)
    print(f"[Elapsed Time][{name}] {format(elapsed_time, '.3f')})")
    print(f"=" * 60)
    print("")
    return elapsed_time

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


def clean_logs():
    cwd = os.getcwd()
    os.chdir('/home/jhshin/work/someip_app/logs')

    # remove '/' at the end of the dirname
    bak_dirs = [d[:-1] for d in os.popen("ls -d bak-*/").read().strip().split("\n")]
    bak_dirs.sort()
    last_bak_dir = bak_dirs[-1]
    last_bak_dir_no = int(last_bak_dir.split("-")[-1])
    new_bak_dir_no = last_bak_dir_no + 1
    new_bak_dir = "bak-" + str(new_bak_dir_no).zfill(3)
    os.system(f"mkdir -p {new_bak_dir}")
    #os.system(f"mv *.log {new_bak_dir}/")

    log_files = os.popen("ls *.log | grep -v ivi.log").read().strip()
    if bool(log_files):
        log_files = " ".join(log_files.split("\n"))
        os.system(f"mv {log_files} {new_bak_dir}/")
    os.chdir(cwd)

def main():

    clean_logs()

    net = Containernet(controller=RemoteController, autoStaticArp=True)

    info('*** Zonal E/E Architecture based In-Vehicle network ***\n')
    info('*** Central Switch(1), Zonal Gateway(4), IVI, Cluster, ADAS, Telematics ***\n')

    vivn_setup_start = time.time()

    node_creation_start = time.time()
    c_sw = net.addSwitch('s1')
    zone_gw_fl = create_node(net, "zone_gw_fl", cpu="0",     mem=1 * 1024 * 1024 * 1024)
    zone_gw_fr = create_node(net, "zone_gw_fr", cpu="1",     mem=1 * 1024 * 1024 * 1024)
    zone_gw_rl = create_node(net, "zone_gw_rl", cpu="2",     mem=1 * 1024 * 1024 * 1024)
    zone_gw_rr = create_node(net, "zone_gw_rr", cpu="3",     mem=1 * 1024 * 1024 * 1024)
    ivi        = create_node(net, "ivi",        cpu="4,5",   mem=4 * 1024 * 1024 * 1024)
    cluster    = create_node(net, "cluster",    cpu="6",     mem=1 * 1024 * 1024 * 1024)
    adas       = create_node(net, "adas",       cpu="7,8",   mem=4 * 1024 * 1024 * 1024)
    telematics = create_node(net, "telematics", cpu="9",     mem=1 * 1024 * 1024 * 1024)
    node_creation_end = time.time()
    t_node_creation = calc_elapsed_time("vECU creation time", \
            node_creation_start, \
            node_creation_end)

    vECUs = [
        zone_gw_fl, zone_gw_fr, zone_gw_rl, zone_gw_rr,
        ivi,        cluster,    adas,       telematics
    ]

    '''

    # debug
    info('*** Setup In-vehicle network\n')
    #adas       = create_node(net, "adas",       cpu="7,8",   mem=4 * 1024 * 1024 * 1024)
    zone_gw_fl = create_node(net, "zone_gw_fl", cpu="0",     mem=1 * 1024 * 1024 * 1024)
    ivi        = create_node(net, "ivi",        cpu="4,5",   mem=4 * 1024 * 1024 * 1024)
    telematics = create_node(net, "telematics", cpu="9",     mem=1 * 1024 * 1024 * 1024)
    vECUs = [telematics, ivi, zone_gw_fl]
    '''

    link_creation_start = time.time()
    for vECU in vECUs:
        #net.addLink(vECU, c_sw, cls=TCLink, bw=100, delay='1ms')
        net.addLink(vECU, c_sw, cls=TCLink, bw=100)
    net.start()
    link_creation_end = time.time()
    t_link_creation = calc_elapsed_time("Virtual Network Link creation time", \
            link_creation_start, \
            link_creation_end)


    # RUNTIME STEP CONFIG
    VLAN_SETTING = True
    ARP_SETTING = True
    MULTICAST_SETTING = True
    PTP_RUN = True
    TFTP_RUN = True
    AVTP_RUN = True
    ROUTING_MANAGER = False
    SOMEIP_SERVICE = False


    # VLAN setting
    t_vlan_setup = 0
    if VLAN_SETTING:
        vlan_setup_start = time.time()
        # VLAN1: PTP
        # VLAN2: AVTP
        # VLAN3: SOME/IP
        for vECU in vECUs:
            vlan_ids = [1, 2, 3]
            for vlan_id in vlan_ids:
                info(f"[{vECU.name}] add vlan {vlan_id}\n")
                vECU.cmd(f'/root/someip_app/utils/add_vlan.sh {vlan_id}')
                #time.sleep(0.1)
        vlan_setup_end = time.time()
        t_vlan_setup = calc_elapsed_time("VLAN setup time", \
                vlan_setup_start, \
                vlan_setup_end)


    # ARP setting
    t_arp_setup = 0
    if ARP_SETTING:
        arp_setup_start = time.time()
        for vECU in vECUs:
            vECU_ids = [1, 2, 3, 4, 5, 6, 7, 8]
            vECU_ids.remove(node_conf[vECU.name]["id"])

            vlan_ids = [1, 3]
            for vlan_id in vlan_ids:
                for vECU_id in vECU_ids:
                    info(f'[{vECU.name}] arp -s 10.0.{vlan_id}.{vECU_id} 00:00:00:00:00:0{vECU_id} -i veth0.{vlan_id}\n')
                    vECU.cmd(f'arp -s 10.0.{vlan_id}.{vECU_id} 00:00:00:00:00:0{vECU_id} -i veth0.{vlan_id}')
                    #time.sleep(0.1)
        arp_setup_end = time.time()
        t_arp_setup = calc_elapsed_time("ARP setup time", \
                arp_setup_start, \
                arp_setup_end)


    # multicast setting
    t_mcast_setup = 0
    if MULTICAST_SETTING:
        mcast_setup_start = time.time()
        info('*** Starting to execute commands\n')
        someip_multicast_ip_list = [
            "239.10.3.1",   # SOME/IP service discovery (239.10.0.x)
            "239.10.3.11",
            "239.10.3.12",
            "239.10.3.13",
            "239.10.3.14",
            "239.10.3.15",
            #"224.0.0.22"    # IGMP
        ]

        ptp_multicast_ip_list = []
        #ptp_multicast_ip_list = [
        #    "224.0.0.107",  # PTP?
        #    "224.0.1.129",  # PTP?
        #    "224.0.1.130"  # PTP?
        #]

        for vECU in vECUs:
            info(f"[{vECU.name}] multicast route setting\n")
            for m_ip in someip_multicast_ip_list:
                info(f"[{vECU.name}] route add -n {m_ip} veth0.3\n")
                route_setup_cmd = f"route add -n {m_ip} veth0.3"
                vECU.cmd(route_setup_cmd)
                #time.sleep(0.1)

            if vECU.name == "telematics":
                for m_ip in ptp_multicast_ip_list:
                    info(f"[{vECU.name}] route add -n {m_ip} veth0.1\n")
                    route_setup_cmd = f"route add -n {m_ip} veth0.1"
                    vECU.cmd(route_setup_cmd)
                    #time.sleep(0.1)
        mcast_setup_end = time.time()
        t_mcast_setup = calc_elapsed_time("Multicast route setup time", \
                mcast_setup_start, \
                mcast_setup_end)


    info(f"OVS actions=NORMAL rule setting\n")
    #c_sw.cmd('ovs-ofctl add-flow s1 "dl_type=0x0800,nw_proto=2,actions=drop"')
    #c_sw.cmd('ovs-ofctl add-flow s1 "priority=100,dl_dst=01:00:5e:00:01:81,dl_vlan=1,actions=strip_vlan,NORMAL"')
    #c_sw.cmd('ovs-vsctl set Bridge s1 mcast_snooping_enable=true')
    c_sw.cmd('ovs-ofctl -O OpenFlow13 add-flow s1 "priority=200,dl_dst=91:ef:00:00:fe:00,dl_vlan=2,actions=FLOOD"')
    c_sw.cmd('ovs-ofctl -O OpenFlow13 add-flow s1 "priority=100,dl_dst=01:80:c2:00:00:0e,dl_vlan=1,actions=FLOOD"')
    c_sw.cmd('ovs-ofctl -O OpenFlow13 add-flow s1 "priority=0,actions=NORMAL"')


    # run PTP daemon
    # [Note!] PTP slave is not working via containernet
    t_ptp_setup = 0
    if PTP_RUN:
        ptp_setup_start = time.time()
        info(f"Run PTP master/slave \n")
        info(f"[Telematics] PTP master\n")
        info(f'/root/someip_app/ptp/ptp4l -S -i veth0.1 -f /root/someip_app/ptp/configs/automotive-master.cfg & \n')
        telematics.cmd(f'/root/someip_app/ptp/ptp4l -S -i veth0.1 -f /root/someip_app/ptp/configs/automotive-master.cfg & \n')
        ptp_setup_end = time.time()
        t_ptp_setup = calc_elapsed_time("PTP master init time", \
                ptp_setup_start, \
                ptp_setup_end)
        

    t_tftp_setup = 0
    if TFTP_RUN:
        tftp_setup_start = time.time()
        info(f'/root/someip_app/pyTFTP/server.py -H 10.0.3.5 -p 8467 /root/someip_app/logs & \n')
        ivi.cmd(f'/root/someip_app/pyTFTP/server.py -H 10.0.3.5 -p 8467 /root/someip_app/logs & \n')
        tftp_setup_end = time.time()
        t_tftp_setup = calc_elapsed_time("TFTP server init time", \
                tftp_setup_start, \
                tftp_setup_end)

    t_avtp_setup = 0
    if AVTP_RUN:
        avtp_setup_start = time.time()
        #adas.cmd('~/someip_app/libavtp/my_example/ieciidc-listener -i veth0.2 -d 91:ef:00:00:fe:00 &')
        #time.sleep(0.5)
        #ivi.cmd(f'python3 ~/someip_app/libavtp/my_example/mpeg-ts-timesync-stdout.py | ~/someip_app/libavtp/my_example/ieciidc-talker -i veth0.2 --prio=1 -d 91:ef:00:00:fe:00 &')
        zone_gw_fr.cmd(f'python3 /root/someip_app/scripts/avtp_talker.py front &')
        zone_gw_rr.cmd(f'python3 /root/someip_app/scripts/avtp_talker.py rear &')
        avtp_setup_end = time.time()
        t_avtp_setup = calc_elapsed_time("AVTP talker init time", \
                avtp_setup_start, \
                avtp_setup_end)

    # SOME/IP routingmanager daemon
    # [Note!] NOT working via containernet
    t_routingm_setup = 0
    if ROUTING_MANAGER:
        routingm_setup_start = time.time()
        for vECU in vECUs:
            info(f"[{vECU.name}] run routing managerd\n")
            vECU.cmd('/root/someip_app/services/routingmanager/run_routingd.sh &')
            time.sleep(0.2)
        routingm_setup_end = time.time()
        t_routingm_setup = calc_elapsed_time("RoutingManager init time", \
                routingm_setup_start, \
                routingm_setup_end)
    

    vECU_dict = {vECU.name: vECU for vECU in vECUs}
    # SOME/IP Service
    service_node = {
        "SteeringWheel": {
            "server": "zone_gw_fl", # 10.0.3.1
            "clients": ["adas"],
            "protocol": "udp"
        },
        "TrafficLight": {
            "server": "telematics", # 10.0.3.8
            "clients": ["adas"],
            "protocol": "udp"
        },
        "Intersection": {
            "server": "telematics", # 10.0.3.8
            "clients": ["adas"],
            "protocol": "udp"
        },
        "ObjectDetection": {
            "server": "adas",       # 10.0.3.7
            "clients": ["ivi"],
            "protocol": "udp"
        },
        "VehicleSpeed": {
            "server": "zone_gw_rr", # 10.0.3.4
            "clients": ["cluster", "ivi", "adas"],
            "protocol": "udp"
        },
        "VehiclePose": {
            "server": "zone_gw_rl", # 10.0.3.3
            "clients": ["adas"],
            "protocol": "udp"
        },
        "VehicleAccel": {
            "server": "zone_gw_fr", # 10.0.3.2
            "clients": ["adas"],
            "protocol": "udp"
        },
        "VehicleLocation": {
            "server": "telematics", # 10.0.3.8
            "clients": ["ivi", "cluster"],
            "protocol": "udp"
        },
        "Transmission": {
            "server": "zone_gw_fl", # 10.0.3.1
            "clients": ["adas", "ivi", "cluster"],
            "protocol": "udp"
        },
        "Driving": {
            "server": "zone_gw_fr", # 10.0.3.2
            "clients": ["adas"],
            "protocol": "udp"
        },
        "Collision": {
            "server": "adas",       # 10.0.3.7
            "clients": ["ivi", "cluster"],
            "protocol": "udp"
        },
        "Logging": {
            "server": "ivi",        # 10.0.3.5
            "clients": ["telematics"],
            "protocol": "tcp"
        }
    }

    '''
    # debug
    service_node = {
        "SteeringWheel": {
            "server": "zone_gw_fl", # 10.0.3.1
            "clients": ["ivi"],
            "protocol": "udp"
        },
        "TrafficLight": {
            "server": "zone_gw_fr", # 10.0.3.2
            "clients": ["cluster"],
            "protocol": "udp"
        },
        "Intersection": {
            "server": "zone_gw_rl", # 10.0.3.3
            "clients": ["adas"],
            "protocol": "udp"
        },
        "ObjectDetection": {
            "server": "zone_gw_rr", # 10.0.3.4
            "clients": ["telematics"],
            "protocol": "udp"
        },
 
    }
    '''

    # [Note!] NOT working via containernet
    t_someip_setup = 0
    if SOMEIP_SERVICE:
        someip_setup_start = time.time()
        # [1] Server start
        info("Start servers")
        for service, node_info in service_node.items():
            server, clients, protocol = node_info['server'], node_info['clients'], node_info['protocol']
            run_server_cmd = f'/root/someip_app/services/{service}/run_server.sh {protocol} 2 &'
            info(f"[{server}] {run_server_cmd}\n")
            vECU_dict[server].cmd(run_server_cmd)
            info("sleep -> 0.5 after run_server.sh\n")
            time.sleep(0.5)

        info("Start clients 10s later after starting server.")
        time.sleep(10)

        # [2] Client start
        # Server/Client SOME/IP service start
        for service, node_info in service_node.items():
            server, clients, protocol = node_info['server'], node_info['clients'], node_info['protocol']
            for client in clients:
                run_client_cmd = f'/root/someip_app/services/{service}/run_client.sh {protocol} 2 &'
                info(f"[{client}] {run_client_cmd}\n")
                vECU_dict[client].cmd(run_client_cmd)
                info("sleep -> 0.5 after run_client.sh\n")
                time.sleep(0.5)
        someip_setup_end = time.time()
        t_someip_setup = calc_elapsed_time("SOME/IP service", \
                        someip_setup_start, \
                        someip_setup_end)

    vivn_setup_end = time.time()

    vivn_setup_elapsed_time = vivn_setup_end - vivn_setup_start
    vivn_setup_elapsed = calc_elapsed_time("Virtualized IVN + vECU setup time", \
                                            vivn_setup_start,
                                            vivn_setup_end)


    info(f"DEBUG===============\n")
    info(f"node_creation: {format(t_node_creation, '.3f')}\n")
    info(f"link_creation: {format(t_link_creation, '.3f')}\n")
    info(f"vlan_setup:    {format(t_vlan_setup, '.3f')}\n")
    info(f"arp/mcast:     {format(t_arp_setup+t_mcast_setup, '.3f')}\n")
    info(f"ptp/avtp/tftp: {format(t_ptp_setup+t_avtp_setup+t_tftp_setup, '.3f')}\n")
    info(f"DEBUG===============")

    info("=" * 50 + '\n')
    info(f"Virtualized IVN + vECUs(8) setup is completed! ({format(vivn_setup_elapsed_time, '.3f')}s)\n")
    info("=" * 50 + '\n')
    CLI(net)
    net.stop()

if __name__ == "__main__":
    main()
