#!/usr/bin/env python3

import argparse
import json
import os
import sys

from subprocess import call
from typing import Optional

from mininet.topo import Topo
from mininet.net import Mininet
from mininet.node import Node
from mininet.log import setLogLevel, info
from mininet.cli import CLI


class LinuxMPLSRouter( Node ):
    "A Node with IP & MPLS forwarding enabled."

    # pylint: disable=arguments-differ
    def config( self, **params ):
        super().config( **params )
        # Enable forwarding on the router
        self.cmd( 'sysctl net.ipv4.ip_forward=1' )
        self.cmd( 'sysctl net.ipv4.conf.all.forwarding=1' )

        # Load mpls kernel modules
        self.cmd('modprobe mpls_router')
        self.cmd('modprobe mpls_iptunnel')
        self.cmd('modprobe mpls_gso')

        # Enable MPLS
        for interface in self.intfNames():
            self.cmd(f"sysctl net.mpls.conf.{interface}.input=1")

        self.cmd('sysctl net.mpls.conf.lo.input=1')
        self.cmd('sysctl net.mpls.platform_labels=100000')

    def terminate( self ):
        self.cmd( 'sysctl net.ipv4.ip_forward=0' )
        self.cmd( 'sysctl net.ipv4.conf.all.forwarding=0' )
        super().terminate()

DEFAULT_LOOPBACK_IP_PREFIX = '10.200.200.'

class NetworkTopo( Topo ):
    def build( self, **_ ): # pylint: disable=arguments-differ

        node_A, node_B, node_C, node_D, node_E, node_Z = [
            self.addNode(s, cls=LinuxMPLSRouter, ip=None)
            for s in ( 'A', 'B', 'C', 'D', 'E', 'Z')
        ]

        info('*** Adding links\n')
        self.addLink(node1=node_A, node2=node_B,
                     params1={ 'ip': '192.168.1.11/24' }, params2={ 'ip': '192.168.1.12/24' },
                     intfName1=f"{node_A}-eth1", intfName2=f"{node_B}-eth1")

        self.addLink(node1=node_A, node2=node_C,
                     params1={ 'ip': '192.168.2.11/24' }, params2={ 'ip': '192.168.2.13/24' },
                     intfName1=f"{node_A}-eth2", intfName2=f"{node_C}-eth1")

        self.addLink(node1=node_B, node2=node_C,
                     params1={ 'ip': '192.168.3.12/24' }, params2={ 'ip': '192.168.3.13/24' },
                     intfName1=f"{node_B}-eth2", intfName2=f"{node_C}-eth2")

        self.addLink(node1=node_B, node2=node_D,
                     params1={ 'ip': '192.168.4.12/24' }, params2={ 'ip': '192.168.4.14/24' },
                     intfName1=f"{node_B}-eth3", intfName2=f"{node_D}-eth1")

        self.addLink(node1=node_C, node2=node_E,
                     params1={ 'ip': '192.168.5.13/24' }, params2={ 'ip': '192.168.5.15/24' },
                     intfName1=f"{node_C}-eth3", intfName2=f"{node_E}-eth1")

        self.addLink(node1=node_D, node2=node_E,
                     params1={ 'ip': '192.168.6.14/24' }, params2={ 'ip': '192.168.6.15/24' },
                     intfName1=f"{node_D}-eth2", intfName2=f"{node_E}-eth2")

        self.addLink(node1=node_D, node2=node_Z,
                     params1={ 'ip': '192.168.7.14/24' }, params2={ 'ip': '192.168.7.16/24' },
                     intfName1=f"{node_D}-eth3", intfName2=f"{node_Z}-eth1")

        self.addLink(node1=node_E, node2=node_Z,
                     params1={ 'ip': '192.168.8.15/24' }, params2={ 'ip': '192.168.8.16/24' },
                     intfName1=f"{node_E}-eth3", intfName2=f"{node_Z}-eth2")

def run(interactive=False):
    topo = NetworkTopo()
    net = Mininet( topo=topo,
                   waitConnected=True )
    net.start()

    info('*** Loading routes\n')

    static_route_file = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                     'static_routes.json')
    try:
        with open(static_route_file, encoding=('utf-8')) as static_route_file:
            static_routes = json.load(static_route_file)

            for i, (node, route_config) in enumerate(static_routes.items()):
                info(f"* {node}:\n")
                net[node].cmd(f'ip addr add "{DEFAULT_LOOPBACK_IP_PREFIX}{i + 1}" dev lo')

                for option, routes in route_config.items():
                    for route in routes:
                        route_cmd = f"ip {option} route add {route}"
                        info(f"\t# {route_cmd}\n")
                        net[node].cmd(route_cmd)
    except Exception as err:   # pylint: disable=broad-except
        net.stop()
        sys.exit(err)


    try:
        net.pingAll()

        call('cd /home/vagrant/ti-mfa-src; make install', shell=True)

        e_A_C_backup_route_args_C = {
            'mac1': net['A'].nameToIntf['A-eth2'].mac,
            'mac2': net['C'].nameToIntf['C-eth1'].mac,
            'label': 1200,
            'dev':'C-eth1',
            'pid': net['C'].pid
        }
        e_B_C_backup_route_args_C = {
            'mac1': net['B'].nameToIntf['B-eth2'].mac,
            'mac2': net['C'].nameToIntf['C-eth2'].mac,
            'label': 1500,
            'dev': 'C-eth3',
            'pid': net['C'].pid
        }
        e_A_C_backup_route_args_E = {
            'mac1': net['A'].nameToIntf['A-eth2'].mac,
            'mac2': net['C'].nameToIntf['C-eth1'].mac,
            'label': 1400,
            'dev':'E-eth2',
            'pid': net['E'].pid
        }

        if interactive:
            info('C: ' + ti_mfa_conf(**e_A_C_backup_route_args_C, dry_run=True) + '\n')
            info('C: ' + ti_mfa_conf(**e_B_C_backup_route_args_C, dry_run=True) + '\n')
            info('E: ' + ti_mfa_conf(**e_A_C_backup_route_args_E, dry_run=True) + '\n')

            CLI(net)

        else:
            call('date', shell=True)

            info('### Testing link failure A-C. Packet should go Z-E-C-B-A')
            net.configLinkStatus('A', 'C', status='down')
            info('C: ' + ti_mfa_conf(**e_A_C_backup_route_args_C) + '\n')
            info(net['Z'].cmd('ping -c 1 10.200.200.1'))

            info('### Testing additionally link failure B-C. Packet should go Z-E-C-E-D-B-A')
            net.configLinkStatus('B', 'C', status='down')

            info('C: ' + ti_mfa_conf(**e_B_C_backup_route_args_C) + '\n')
            info('E: ' + ti_mfa_conf(**e_A_C_backup_route_args_E) + '\n')

            info(net['Z'].cmd('ping -c 1 10.200.200.1'))

    finally:
        call('rmmod ti_mfa || true', shell=True)
        net.stop()

def ti_mfa_conf(mac1: str, mac2: str, label: int, dev: str, pid: Optional[int] = None,
                dry_run: bool = False):
    command = f"ti-mfa-conf add {mac1}-{mac2} {label} {dev}"

    if pid:
        command += f" {pid}"

    if not dry_run:
        call(command, shell=True)

    return command


def parse_args():
    parser = argparse.ArgumentParser()
    parser.add_argument('-i', '--interactive', const=True, default=False,
                        action='store_const', help='set interactive')
    return parser.parse_args()

if __name__ == '__main__':
    setLogLevel( 'info' )
    ARGS = parse_args()
    run(interactive=ARGS.interactive)
