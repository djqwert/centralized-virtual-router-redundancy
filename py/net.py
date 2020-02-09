#!/usr/bin/python

from mininet.net import Mininet
from mininet.node import Controller, RemoteController, OVSController
from mininet.node import Host, Node
from mininet.node import OVSKernelSwitch, UserSwitch
from mininet.cli import CLI
from mininet.log import setLogLevel, info

class LinuxRouter( Node ):
    "A Node with IP forwarding enabled."

    def config( self, **params ):
        super( LinuxRouter, self).config( **params )
        # Enable forwarding on the router
        self.cmd( 'sysctl net.ipv4.ip_forward=1' )

    def terminate( self ):
        self.cmd( 'sysctl net.ipv4.ip_forward=0' )
        super( LinuxRouter, self ).terminate()

def myNetwork():

    net = Mininet( topo=None, build=False, ipBase='10.0.0.0/24')
    virtualAddress = 'via 10.0.2.254'

    info( '*** Adding controller\n' )
    c0=net.addController(name='c0',
                      controller=RemoteController,
                      ip='127.0.0.1',
                      protocol='tcp',
                      port=6653)

    info( '*** Add routers\n')
    r1 = net.addHost('r1', cls=LinuxRouter, ip='10.0.2.1/24', mac='00:00:00:00:00:01')
    r2 = net.addHost('r2', cls=LinuxRouter, ip='10.0.2.2/24', mac='00:00:00:00:00:02')
    
    info( '*** Add switches\n')
    s1 = net.addSwitch('s1', cls=OVSKernelSwitch)    
    s2 = net.addSwitch('s2', cls=OVSKernelSwitch, failMode='standalone')

    info( '*** Add hosts\n')
    h1 = net.addHost('h1', cls=Host, ip='10.0.2.3/24', defaultRoute=virtualAddress)
    h2 = net.addHost('h2', cls=Host, ip='10.0.2.4/24', defaultRoute=virtualAddress)
    h3 = net.addHost('h3', cls=Host, ip='10.0.2.5/24', defaultRoute=virtualAddress)
    h4 = net.addHost('h4', cls=Host, ip='10.0.3.3/24', defaultRoute='via 10.0.3.2')
    h5 = net.addHost('h5', cls=Host, ip='10.0.3.4/24', defaultRoute='via 10.0.3.2')

    info( '*** Add links\n')
    net.addLink(h1, s1, 1, 1)
    net.addLink(h2, s1, 1, 2)
    net.addLink(h3, s1, 1, 3)
    net.addLink(s1, r1, 4, 1, params2={ 'ip' : '10.0.2.1/24' })
    net.addLink(s1, r2, 5, 1, params2={ 'ip' : '10.0.2.2/24' })
    net.addLink(s2, r1, 4, 2, params2={ 'ip' : '10.0.3.1/24' })
    net.addLink(s2, r2, 5, 2, params2={ 'ip' : '10.0.3.2/24' })
    net.addLink(h4, s2, 1, 1)
    net.addLink(h5, s2, 1, 2)
    net.addLink(h6, s2, 1, 3)

    info( '*** Starting network\n')
    net.build()
    
    info( '*** Starting controllers\n')
    for controller in net.controllers:
        controller.start()

    info( '*** Starting switches\n')
    net.get('s2').start([])
    net.get('s1').start([c0])

    info( '*** Post configure switches and hosts\n')

    CLI(net)
    
    net.stop()

if __name__ == '__main__':
    setLogLevel( 'info' )
    myNetwork()