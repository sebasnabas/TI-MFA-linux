#!/usr/bin/env python3

import json
import os
import sys

from mininet.topo import Topo
from mininet.net import Mininet
from mininet.node import Node
from mininet.log import setLogLevel, info
from mininet.cli import CLI


class LinuxMPLSRouter( Node ):
    "A Node with IP forwarding enabled."

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
    # pylint: disable=arguments-differ
    def build( self, **_ ):

        node_t, node_l, node_m, node_r = [
            self.addNode(s, cls=LinuxMPLSRouter, ip=None)
            for s in ( 'T', 'L', 'M', 'R' )
        ]

        info('*** Adding links\n')
        self.addLink(node1=node_t, node2=node_l,
                     params1={ 'ip': '192.168.1.11/24' }, params2={ 'ip': '192.168.1.12/24' },
                     intfName1=f"{node_t}-eth1", intfName2=f"{node_l}-eth1")

        self.addLink(node1=node_t, node2=node_m,
                     params1={ 'ip': '192.168.2.11/24' }, params2={ 'ip': '192.168.2.13/24' },
                     intfName1=f"{node_t}-eth2", intfName2=f"{node_m}-eth2")

        self.addLink(node1=node_t, node2=node_r,
                     params1={ 'ip': '192.168.3.11/24' }, params2={ 'ip': '192.168.3.14/24' },
                     intfName1=f"{node_t}-eth3", intfName2=f"{node_r}-eth2")

        self.addLink(node1=node_l, node2=node_m,
                     params1={ 'ip': '192.168.4.12/24' }, params2={ 'ip': '192.168.4.13/24' },
                     intfName1=f"{node_l}-eth2", intfName2=f"{node_m}-eth1")

        self.addLink(node1=node_m, node2=node_r,
                     params1={ 'ip': '192.168.5.13/24' }, params2={ 'ip': '192.168.5.14/24' },
                     intfName1=f"{node_m}-eth3", intfName2=f"{node_r}-eth1")

def run():
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

    CLI( net )
    net.stop()


if __name__ == '__main__':
    setLogLevel( 'info' )
    run()
