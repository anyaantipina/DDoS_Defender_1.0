from mininet.topo import Topo
from mininet.net import Mininet
from mininet.net import Host
from mininet.node import RemoteController
from mininet.net import OVSKernelSwitch
from mininet.util import dumpNodeConnections
from mininet.util import partial
from mininet.log import setLogLevel
from mininet.link import Link
from mininet.cli import CLI
from mininet.log import info, output, warn, setLogLevel
import os
import sys
from time import monotonic
from time import sleep
from mininet.topolib import TreeNet


#     runos
#     /   \
#   s1-----s2
#   /\     /\
# h1  h2 h3  h4
class MyTopo(Topo):
    def build( self, countH=2, countS=2 ):                                                                            
        switches = [ self.addSwitch( 's%d' % i )                                                                                   
                  for i in range( 1, countS + 1 ) ] 
        j=0                                                                          
        for s in switches: 
            if j>0 :
                self.addLink(s,prevsw)
            for i in range(countH):     
                h = self.addHost( 'h%d' % (i+1+j) )                                                                                                  
                self.addLink( h, s )
            j+=countH
            prevsw = s
    


#       runos
#         |
#         s1
#      /      \
#    s2        s4
#   /  \       |  \
# h1_2  s3     s5  s6
#      /  \     |   \
#  h3_1  h3_2  h5_1  h6_1
class MyTopoSecond(Topo):
    def build( self):                    
        
        s1 = self.addSwitch('s1')
        s2 = self.addSwitch('s2')
        h2_1 = self.addHost('h2_1')  
        self.addLink(h2_1,s2)
        s3 = self.addSwitch('s3')
        h3_1 = self.addHost('h3_1')
        self.addLink(h3_1, s3)  
        h3_2 = self.addHost('h3_2')
        self.addLink(h3_2, s3)
        s4 = self.addSwitch('s4')
        s5 = self.addSwitch('s5')
        h5_1 = self.addHost('h5_1')
        self.addLink(h5_1, s5)
        s6 = self.addSwitch('s6')
        h6_1 = self.addHost('h6_1')
        self.addLink(h6_1, s6)
    
        self.addLink(s4,s6)
        self.addLink(s4,s5)
        self.addLink(s1,s4)
        self.addLink(s2,s3) 
        self.addLink(s1,s2)


def printConnections( switches ):
    "Compactly print connected nodes to each switch"
    for sw in switches:
        output( '%s: ' % sw )
        for intf in sw.intfList():
            link = intf.link
            if link:
                intf1, intf2 = link.intf1, link.intf2
                remote = intf1 if intf1.node != sw else intf2
                output( '%s(%s) ' % ( remote.node, sw.ports[ intf ] ) )
        output( '\n' )

def deleteHost( host, switch,  net ):
    #host: host object
    #switch: switch object
    #net: net object
    link = net.linksBetween(host,switch)[0]
    net.delLink(link)
    host.stop()
    host.terminate()
    net.delHost(host)

def deleteSwitch( nodes, switch, net ):
    intfs = []
    for node in nodes:
        print(node.name)
        intfs+=switch.connectionsTo(node)
        net.delLinkBetween(switch,node)
    for src,dst in intfs:
        print(src.name, dst.name)
    switch.stop()
    switch.terminate()
    net.switches.remove(switch)
    for node in nodes:
        if node in net.hosts:
            net.hosts.remove(node)


def addHost(host, mac, ip, switch, port, net):
    #host, mac, ip: string
    #switch: switch object
    #port: integer
    #net: net object
    net.addHost(host, mac=mac, ip=ip)
    options = dict()
    if port is not None:
        options.setdefault( 'port2', port)
    if mac is not None:
        options.setdefault( 'addr1', mac)
    if port is not None:
        net.addLink(net.get(host), switch, **options)
        intfs = switch.intfList()
        switch.attach(intfs[port])
    else:
        net.addLink(net.get(host), switch, **options)
        intfs = switch.intfList()
        switch.attach(intfs[-1])
    new_host = net.get(host)
    new_host.cmd('ifconfig lo up')
    new_host.cmd('ifconfig %s-eth0 %s/8 up' % (host, ip))

def SwitchOff(switch, net):
    #switch: switch object
    #net: net object
    sw_name = switch.name
    links = []
    for link in net.links:
        node = link.intf1.node
        if node.name == sw_name:
            node = link.intf2.node
        if (link.intf1.node.name == sw_name) | (link.intf2.node.name == sw_name):
            links.append(link)
    for link in links:
        net.configLinkStatus(link.intf1.node.name, link.intf2.node.name, 'down')

def SwitchUp(switch, net):
    #switch: switch object
    #net: net object
    #intfs = switch.intfs
    sw_name = switch.name
    links = []
    for link in net.links:
        node = link.intf1.node
        if node.name == sw_name:
            node = link.intf2.node
        if (link.intf1.node.name == sw_name) | (link.intf2.node.name == sw_name):
            links.append(link)
    for link in links:
        net.configLinkStatus(link.intf1.node.name, link.intf2.node.name, 'up')


def moveHost(host, oldSwitch, newSwitch, swPort, net):
    #host: host object
    #oldSwitch, newSwitch: switch object
    #swPort: integer
    #net: net object
    hintf, sintf = host.connectionsTo( oldSwitch )[ 0 ]
    oldSwitch.detach(sintf)
    if swPort is not None:
        net.addLink(host, newSwitch, port2=swPort, addr1=host.MAC())
    else:
        net.addLink(host, newSwitch, addr1=host.MAC())
    Sintfs = newSwitch.intfList()
    if swPort is not None:
        newSwitch.attach(Sintfs[swPort])
    else:
        newSwitch.attach(Sintfs[-1])
    Hintfs = host.intfList()
    host.cmd('ifconfig lo up')
    host.cmd('ifconfig %s %s/8 up' % (Hintfs[-1], host.IP()))
    link = net.linksBetween(host,oldSwitch)[0]
    net.delLink(link)

    

def simpleTest():
    controller = RemoteController('Runos', ip='192.168.56.102', port=6653)
    switch = partial(OVSKernelSwitch, protocols='OpenFlow13')
    net = TreeNet(depth=2, fanout=3, controller=controller, switch=switch, cleanup=True)
    net.start()
    sleep(3)
    start = monotonic()

    results = []
    childs = []
    for hostName in net.topo.hosts():
        try :
            pid = os.fork()
        except :
            print( 'error: create child process' ); sys.exit( 33 )
        if pid == 0:
            host = net.get(hostName)
            
            if hostName == "h1":
                pingPair = net.get("h4")
                
                curr_time = monotonic() - start
                interval = (12 - curr_time) if (12 - curr_time) >=1 else 1
                print("curr_time=%s :: %s start ping %s for %s sec" % (curr_time, host.IP(), pingPair.IP(), interval))
                print(hostName, host.cmd("./png.sh %s %s" % (pingPair.IP(),interval)))
                
                curr_time = monotonic() - start
                sleep_time = 12.5 - curr_time
                if sleep_time > 0:
                    sleep(sleep_time)

                curr_time = monotonic() - start
                print("curr_time=%s :: %s start attack" % (curr_time, host.IP()))
                result = host.cmd("./atck.sh %s %s 25" % (host.MAC(), host.IP()))
                print("%s end attack" % host.IP())

            if hostName == "h2":
                pingPair = net.get("h1")

                curr_time = monotonic() - start
                interval = (4 - curr_time) if (4 - curr_time) >=1 else 1
                print("curr_time=%s :: %s start ping %s for %s sec" % (curr_time, host.IP(), pingPair.IP(), interval))
                print(hostName, host.cmd("./png.sh %s %s" % (pingPair.IP(),interval)))

                curr_time = monotonic() - start
                print('curr_time=%s :: %s changed IP with DHCP' % (curr_time, host.IP()))
                host.cmd('dhclient -r')
                host.cmd('dhclient')
                sleep(0.5)
                newIP = host.cmd("ifconfig | grep 'inet 10.' | cut -f2 -d't' | cut -f1 -d'n'")
                splitnewIP = newIP.split(' ')
                host.setIP(splitnewIP[1])

                pingPair = net.get("h3")
                pingPair.setIP("10.0.0.20")
                curr_time = monotonic() - start
                sleep_time = 6 - curr_time
                if sleep_time > 0:
                    sleep(sleep_time)

                curr_time = monotonic() - start
                interval = (12 - curr_time) if (12 - curr_time) >=1 else 1
                print("curr_time=%s :: %s start ping %s for %s sec" % (curr_time, host.IP(),pingPair.IP(), interval))
                print(hostName, host.cmd("./png.sh %s %s" % (pingPair.IP(),interval)))

                curr_time = monotonic() - start
                sleep_time = 12.5 - curr_time
                if sleep_time > 0:
                    sleep(sleep_time)

                curr_time = monotonic() - start
                print("curr_time=%s :: %s start attack" % (curr_time,host.IP()))
                result = host.cmd("./atck.sh %s %s 25" % (host.MAC(), host.IP()))
                print("%s end attack" % host.IP())

            if hostName == "h3":
                pingPair = net.get("h9")

                curr_time = monotonic() - start
                interval = (4 - curr_time) if (4 - curr_time) >=1 else 1
                print("curr_time=%s :: %s start ping %s for %s sec" % (curr_time, host.IP(), pingPair.IP(), interval))
                print(hostName, host.cmd("./png.sh %s %s" % (pingPair.IP(),interval)))

                curr_time = monotonic() - start
                print('curr_time=%s :: %s changed IP STATIC (%s -> 10.0.0.20)' % (curr_time, host.IP(), host.IP()))
                host.cmd('ifconfig h3-eth0 10.0.0.20 netmask 255:0:0:0')
                host.setIP("10.0.0.20")
                sleep(0.5)

                pingPair = net.get("h9")
                curr_time = monotonic() - start
                sleep_time = 6 - curr_time
                if sleep_time > 0:
                    sleep(sleep_time)

                curr_time = monotonic() - start
                interval = (17 - curr_time) if (17 - curr_time) >=1 else 1
                print("curr_time=%s :: %s start ping %s for %s sec" % (curr_time, host.IP(), pingPair.IP(), interval))
                print(hostName, host.cmd("./png.sh %s %s" % (pingPair.IP(),interval)))

                pingPair = net.get("h4")
                curr_time = monotonic() - start
                interval = (25 - curr_time) if (25 - curr_time) >=1 else 1
                print("curr_time=%s :: %s start ping %s for %s sec" % (curr_time, host.IP(), pingPair.IP(), interval))
                result = host.cmd("./png.sh %s %s" % (pingPair.IP(),interval))
                handle = open("outputH3-H4.txt", "w")
                handle.write(result)
                handle.close()

                pingPair = net.get("h7")
                curr_time = monotonic() - start
                interval = (40 - curr_time) if (40 - curr_time) >=1 else 1
                print("curr_time=%s :: %s start ping %s for %s sec" % (curr_time, host.IP(), pingPair.IP(), interval))
                print(hostName, host.cmd("./png.sh %s %s" % (pingPair.IP(),interval)))

                pingPair = net.get("h6")
                curr_time = monotonic() - start
                interval = (50 - curr_time) if (50 - curr_time) >=1 else 1
                print("curr_time=%s :: %s start ping %s for %s sec" % (curr_time, host.IP(), pingPair.IP(), interval))
                print(hostName, host.cmd("./png.sh %s %s" % (pingPair.IP(),interval)))

            if hostName == "h4":
                pingPair = net.get("h5")

                curr_time = monotonic() - start
                interval = (17 - curr_time) if (17 - curr_time) >=1 else 1
                print("curr_time=%s :: %s start ping %s for %s sec" % (curr_time, host.IP(), pingPair.IP(), interval))
                print(hostName, host.cmd("./png.sh %s %s" % (pingPair.IP(),interval)))

                pingPair = net.get("h6")
                curr_time = monotonic() - start
                interval = (25 - curr_time) if (25 - curr_time) >=1 else 1
                print("curr_time=%s :: %s start ping %s for %s sec" % (curr_time, host.IP(), pingPair.IP(), interval))
                result = host.cmd("./png.sh %s %s" % (pingPair.IP(),interval))
                handle = open("outputH4-H6.txt", "w")
                handle.write(result)
                handle.close()

                curr_time = monotonic() - start
                print('curr_time=%s :: %s changed IP with DHCP' % (curr_time, host.IP()))
                host.cmd('dhclient -r')
                host.cmd('dhclient')
                sleep(0.5)
                newIP = host.cmd("ifconfig | grep 'inet 10.' | cut -f2 -d't' | cut -f1 -d'n'")
                splitnewIP = newIP.split(' ')
                host.setIP(splitnewIP[1])

                pingPair = net.get("h6")
                curr_time = monotonic() - start
                sleep_time = 27.5 - curr_time
                if sleep_time > 0:
                    sleep(sleep_time)

                curr_time = monotonic() - start
                interval = (50 - curr_time) if (50 - curr_time) >=1 else 1
                print("curr_time=%s :: %s start ping %s for %s sec" % (curr_time, host.IP(), pingPair.IP(), interval))
                print(hostName, host.cmd("./png.sh %s %s" % (pingPair.IP(),interval)))


            if hostName == "h5":
                pingPair = net.get("h6")
                
                curr_time = monotonic() - start
                interval = (6 - curr_time) if (6 - curr_time) >=1 else 1
                print("curr_time=%s :: %s start ping %s for %s sec" % (curr_time, host.IP(), pingPair.IP(), interval))
                print(hostName, host.cmd("./png.sh %s %s" % (pingPair.IP(),interval)))

                pingPair = net.get("h8")
                curr_time = monotonic() - start
                interval = (12 - curr_time) if (12 - curr_time) >=1 else 1
                print("curr_time=%s :: %s start ping %s for %s sec" % (curr_time, host.IP(), pingPair.IP(), interval))
                print(hostName, host.cmd("./png.sh %s %s" % (pingPair.IP(),interval)))
                
                curr_time = monotonic() - start
                sleep_time = 12.5 - curr_time
                if sleep_time > 0:
                    sleep(sleep_time)

                curr_time = monotonic() - start
                print("curr_time=%s :: %s start attack" % (curr_time, host.IP()))
                result = host.cmd("./atck.sh %s %s 35" % (host.MAC(), host.IP()))
                print("%s end attack" % host.IP())

            if hostName == "h6":
                pingPair = net.get("h7")
                curr_time = monotonic() - start
                interval = (6 - curr_time) if (6 - curr_time) >=1 else 1
                print("curr_time=%s :: %s start ping %s for %s sec" % (curr_time, host.IP(), pingPair.IP(), interval))
                print(hostName, host.cmd("./png.sh %s %s" % (pingPair.IP(),interval)))

                pingPair = net.get("h8")
                curr_time = monotonic() - start
                interval = (27.5 - curr_time) if (27.5 - curr_time) >=1 else 1
                print("curr_time=%s :: %s start ping %s for %s sec" % (curr_time, host.IP(), pingPair.IP(), interval))
                print(hostName, host.cmd("./png.sh %s %s" % (pingPair.IP(),interval)))

                pingPair = net.get("h7")
                curr_time = monotonic() - start
                interval = (50 - curr_time) if (50 - curr_time) >=1 else 1
                print("curr_time=%s :: %s start ping %s for %s sec" % (curr_time, host.IP(), pingPair.IP(), interval))
                print(hostName, host.cmd("./png.sh %s %s" % (pingPair.IP(),interval)))

            if hostName == "h7":
                pingPair = net.get("h9")
                curr_time = monotonic() - start
                interval = (6 - curr_time) if (6 - curr_time) >=1 else 1
                print("curr_time=%s :: %s start ping %s for %s sec" % (curr_time, host.IP(), pingPair.IP(), interval))
                print(hostName, host.cmd("./png.sh %s %s" % (pingPair.IP(),interval)))

                curr_time = monotonic() - start
                sleep_time = 10 - curr_time
                if sleep_time > 0:
                    sleep(sleep_time)

                curr_time = monotonic() - start
                print('curr_time=%s :: %s move from s4 to s2' % (curr_time,host.IP()))
                hostIP = host.IP()
                moveHost(host, net.get('s4'), net.get('s2'), None, net)
                host = net.get(hostName)
                host.setIP(hostIP)

                curr_time = monotonic() - start
                sleep_time = 17 - curr_time
                if sleep_time > 0:
                    sleep(sleep_time)

                pingPair = net.get("h8")
                curr_time = monotonic() - start
                interval = (27.5 - curr_time) if (27.5 - curr_time) >=1 else 1
                print("curr_time=%s :: %s start ping %s for %s sec" % (curr_time, host.IP(), pingPair.IP(), interval))
                result = host.cmd("./png.sh %s %s" % (pingPair.IP(),interval))
                handle = open("outputH7-H8.txt", "w")
                handle.write(result)
                handle.close()

                pingPair = net.get("h9")
                curr_time = monotonic() - start
                interval = (50 - curr_time) if (50 - curr_time) >=1 else 1
                print("curr_time=%s :: %s start ping %s for %s sec" % (curr_time, host.IP(), pingPair.IP(), interval))
                print(hostName, host.cmd("./png.sh %s %s" % (pingPair.IP(),interval)))

            if hostName == "h8":
                pingPair = net.get("h9")
                curr_time = monotonic() - start
                interval = (15 - curr_time) if (15 - curr_time) >=1 else 1
                print("curr_time=%s :: %s start ping %s for %s sec" % (curr_time, host.IP(), pingPair.IP(), interval))
                print(hostName, host.cmd("./png.sh %s %s" % (pingPair.IP(),interval)))

                curr_time = monotonic() - start
                interval = (27.5 - curr_time) if (27.5 - curr_time) >=1 else 1
                print("curr_time=%s :: %s start ping 10.0.0.20 for %s sec" % (curr_time, host.IP(), interval))
                print(hostName, host.cmd("./png.sh 10.0.0.20 %s" % interval))
                curr_time = monotonic() - start
                sleep_time = 30 - curr_time
                if sleep_time > 0:
                    sleep(sleep_time)

                curr_time = monotonic() - start
                print('curr_time=%s :: %s move from s4 to s1' % (curr_time,host.IP()))
                hostIP = host.IP()
                moveHost(host, net.get('s4'), net.get('s1'), None, net)
                host = net.get(hostName)
                host.setIP(hostIP)

                curr_time = monotonic() - start
                sleep_time = 37.5 - curr_time
                if sleep_time > 0:
                    sleep(sleep_time)

                pingPair = net.get("h9")
                curr_time = monotonic() - start
                interval = (50 - curr_time) if (50 - curr_time) >=1 else 1
                print("curr_time=%s :: %s start ping %s for %s sec" % (curr_time, host.IP(), pingPair.IP(), interval))
                print(hostName, host.cmd("./png.sh %s %s" % (pingPair.IP(),interval)))
            
            if hostName == "h9":
                pingPair = net.get("h6")
                curr_time = monotonic() - start
                interval = (50 - curr_time) if (50 - curr_time) >=1 else 1
                print("curr_time=%s :: %s start ping %s for %s sec" % (curr_time, host.IP(), pingPair.IP(), interval))
                print(hostName, host.cmd("./png.sh %s %s" % (pingPair.IP(),interval)))


            sys.exit(3)
        if pid > 0 :
            childs.append( pid )

    curr_time = monotonic() - start
    sleep_time = 27.5 - curr_time
    if sleep_time > 0:
        sleep(sleep_time)
    print('"curr_time=%s :: switch s2 off' % curr_time)
    SwitchOff(net.get('s2'), net)

    curr_time = monotonic() - start
    sleep_time = 40 - curr_time
    if sleep_time > 0:
        sleep(sleep_time)
    print('"curr_time=%s :: switch s2 up' % curr_time)
    SwitchUp(net.get('s2'), net)

    for p in childs :
        pid, status = os.wait()
    print('childs end')

    handleResult = open("outputRTT.txt", "w")
    handle = open("outputH3-H4.txt", "r")
    result = handle.read()
    handleResult.write(result)
    handle.close()
    handle = open("outputH4-H6.txt", "r")
    result = handle.read()
    handleResult.write(result)
    handle.close()
    handle = open("outputH7-H8.txt", "r")
    result = handle.read()
    handleResult.write(result)
    handle.close()
    handleResult.close()


    try :
        pid = os.fork()
    except :
        print( 'error: create child process' ); sys.exit( 33 )
    if pid == 0:
        host = net.get("h1")
        host.cmd("sudo rm outputH3-H4.txt outputH4-H6.txt outputH7-H9.txt")
        sys.exit(3)
    pid, status = os.wait()

    CLI(net)
    net.stop()
    """
    print ("network connections:")
    printConnections(net.switches)

    h1 = net.get('h1')

    print('ping h1->h2')
    print(h1.cmd('ping 10.0.0.2 -c 4'))
    print('ping h1->h3')
    print(h1.cmd('ping 10.0.0.3 -c 4'))

    print('changed IP with DHCP (%s)' % h1.IP())
    h1.cmd('dhclient -r')
    h1.cmd('dhclient')
    sleep(2)
    print(h1.cmd('ping 10.0.0.2 -c 4'))

    h1 = net.get('h1')
    print('changed IP STATIC (%s -> 10.0.0.20)' % h1.IP())
    h1.cmd('ifconfig h1-eth0 10.0.0.20 netmask 255:0:0:0')
    sleep(2)
    print(h1.cmd('ping 10.0.0.2 -c 4'))

    h1 = net.get('h1')
    print('delete host (%s)' % h1.IP())
    deleteHost(h1, net.get('s2'), net)
    print ("network connections:")
    printConnections(net.switches)
    sleep(3)

    print('add host 10.0.0.10')
    addHost('new', None, '10.0.0.10', net.get('s2'), None, net)
    print ("network connections:")
    printConnections(net.switches)
    new = net.get('new')
    print('ping new->h4')
    print(new.cmd('ping 10.0.0.4 -c 4'))


    print('move host %s' % net.get('h3').IP())
    host_3_IP = net.get('h3').IP()
    moveHost(net.get('h3'), net.get('s2'), net.get('s3'), None, net)
    print ("network connections:")
    printConnections(net.switches)
    h3 = net.get('h3')
    print('ping h3->h4')
    print(h3.cmd('ping 10.0.0.4 -c 4'))
    
    print('switch off s3')
    SwitchOff(net.get('s3'), net)
    print ("network connections:")
    printConnections(net.switches)
    sleep(3)

    print('switch up s3')
    SwitchUp(net.get('s3'), net)
    print ("network connections:")
    printConnections(net.switches)
    sleep(3)

    h3 = net.get('h3')
    print('ping h3->h4')
    print(h3.cmd('ping 10.0.0.4 -c 4'))
    sleep(3)

    host_2 = net.get('h2')
    host_3 = net.get('h3')
    host_3.setIP(host_3_IP)
    host_4 = net.get('h4')
    host_new = net.get('new')
    host_new.setIP("10.0.0.10")
    print("h2 has ip %s" % host_2.IP())
    print("h3 has ip %s" % host_3.IP())
    print("h4 has ip %s" % host_4.IP())
    print("h_new has ip %s" % host_new.IP())

    print(host_2.cmd('ping 10.0.0.3 -c 4'))
    h4 = net.get('h4')
    print(h4.cmd("ping %s -c 4" % host_2.IP()))
    print(h3.cmd("ping 10.0.0.4 -c 4"))

    hosts = [host_2, host_4]
    childs = []
    sec = 15
    for host in hosts:
        if host.IP()==host_2.IP():
            sec=15
        if host.IP()==host_4.IP():
            sec=60
        try :
            pid = os.fork()
        except :
            print( 'error: create child process' ); sys.exit( 33 )
        if pid == 0:
            print ("%s start attack" % host.IP())
            result = host.cmd("./runos/src/apps/ddos-defender/scripts/atck.sh %s %s %s" % (host.MAC(), host.IP(), sec))
            sys.exit(3)
        if pid > 0 :
            childs.append( pid )
    
    for p in childs :
        pid, status = os.wait()
    print('end attack')
    sleep(3)

    """

if __name__ == '__main__':
    # Tell mininet to print useful information
    setLogLevel('info')
    simpleTest()
