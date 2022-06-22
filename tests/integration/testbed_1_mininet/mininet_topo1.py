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

        # Load mpls kernel modules
        self.cmd('modprobe mpls_router')
        self.cmd('modprobe mpls_iptunnel')

        # Enable MPLS
        for interface in self.intfNames():
            self.cmd(f"sysctl net.mpls.conf.{interface}.input=1")

        self.cmd('sysctl net.mpls.platform_labels=100000')

    def terminate( self ):
        self.cmd( 'sysctl net.ipv4.ip_forward=0' )
        super().terminate()


class NetworkTopo( Topo ):
    # pylint: disable=arguments-differ
    def build( self, **_ ):

        # default_ip_prefix = '10.200.200.'
# , ip=f"{default_ip_prefix}{i + 1}"
        node_t, node_l, node_m, node_r = [
            self.addNode(s, cls=LinuxMPLSRouter, ip=None)
            for i, s in enumerate(( 'T', 'L', 'M', 'R' ))
        ]

        info('*** Adding links\n')
        self.addLink(node1=node_t, node2=node_l,
                     params1={ 'ip': '192.168.1.11/32' }, params2={ 'ip': '192.168.1.12/32' },
                     intfName1='T-L_eth1', intfName2='L-T_eth1')

        self.addLink(node1=node_t, node2=node_m,
                     params1={ 'ip': '192.168.2.11/32' }, params2={ 'ip': '192.168.2.13/32' },
                     intfName1='T-M_eth2', intfName2='M-T_eth2')

        self.addLink(node1=node_t, node2=node_r,
                     params1={ 'ip': '192.168.3.11/32' }, params2={ 'ip': '192.168.3.14/32' },
                     intfName1='T-R_eth3', intfName2='R-T_eth2')

        self.addLink(node1=node_l, node2=node_m,
                     params1={ 'ip': '192.168.4.12/32' }, params2={ 'ip': '192.168.4.13/32' },
                     intfName1='L-M_eth2', intfName2='M-L_eth1')

        self.addLink(node1=node_m, node2=node_r,
                     params1={ 'ip': '192.168.5.13/32' }, params2={ 'ip': '192.168.5.14/32' },
                     intfName1='M-R_eth3', intfName2='R-M_eth1')

def run():
    topo = NetworkTopo()
    net = Mininet( topo=topo,
                   waitConnected=True )  # controller is used by s1-s3
    net.start()

    info('*** Loading routes')

    static_route_file = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                     'static_routes.json')
    try:
        with open(static_route_file, encoding=('utf-8')) as static_route_file:
            static_routes = json.load(static_route_file)

            for i, (node, route_config) in enumerate(static_routes.items()):
                # net[node].setIP(f"10.200.200.{i}", intf='lo')

                for option, routes in route_config.items():
                    for route in routes:
                        net[node].cmd(f"ip route {option} add {route}")
    except Exception as err:   # pylint: disable=broad-except
        net.stop()
        sys.exit(err)

    info( '*** Routing Table on Router:\n' )
    info( net[ 'T' ].cmd( 'route' ) )
    CLI( net )
    net.stop()


if __name__ == '__main__':
    setLogLevel( 'info' )
    run()
