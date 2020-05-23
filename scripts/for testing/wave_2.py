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

from random import randint
  

def simpleTest():
    print("infection hosts rate:")
    inf_rate = eval(input())
    print("amplituda (packets per second):")
    max = eval(input())
    print("period T:")
    grow_time = eval(input())/2
    atck_time = 40
    test_time = 50


    controller = RemoteController('Runos', ip='127.0.0.1', port=6653)
    switch = partial(OVSKernelSwitch, protocols='OpenFlow13')
    net = TreeNet(depth=2, fanout=3, controller=controller, switch=switch, cleanup=True)
    net.start()
    sleep(3)

    hosts = net.topo.hosts()
    inf_amount = round(inf_rate*len(hosts))
    inf_hosts = []
    while inf_amount:
        num = randint(0,8)
        if inf_amount and not(hosts[num] in inf_hosts):
            inf_hosts.append(hosts[num])
            inf_amount-=1
    hosts = net.topo.hosts()
    general_capacity_per_sec = max / len(inf_hosts)
    num_intervals = round(grow_time / 2)
    offset_delay = round((1000 / general_capacity_per_sec) / num_intervals)

    print(hosts)

    start = monotonic()

    childs = []

    for i in range(len(hosts)):
        try :
            pid = os.fork()
        except :
            print( 'error: create child process' ); sys.exit( 33 )
        if pid == 0:
            host = net.get(hosts[i])

            if hosts[i] in inf_hosts:

                ping_pair = net.get(hosts[i-1])
                curr_time = monotonic() - start
                interval = (2.5 - curr_time) if (2.5 - curr_time) >=1 else 1
                print("curr_time=%s :: %s start ping %s for %s sec" % (curr_time, host.IP(), ping_pair.IP(), interval))
                host.cmd("./runos/src/apps/ddos-defender/scripts/png.sh %s %s" % (ping_pair.IP(),interval))

                ping_pair = net.get(hosts[i-2])
                curr_time = monotonic() - start
                interval = (5 - curr_time) if (5 - curr_time) >=1 else 1
                print("curr_time=%s :: %s start ping %s for %s sec" % (curr_time, host.IP(), ping_pair.IP(), interval))
                host.cmd("./runos/src/apps/ddos-defender/scripts/png.sh %s %s" % (ping_pair.IP(),interval))

                k=0
                while curr_time < atck_time+5:
                    curr_time = monotonic() - start
                    sleep_time = grow_time*2*k+5 - curr_time
                    if sleep_time > 0:
                        sleep(sleep_time)
                    send_delay=0
                    for j in range(num_intervals) :
                        curr_time = monotonic() - start
                        send_delay += offset_delay
                        if (curr_time+2 < atck_time+5) :
                            print("curr_time=%s :: %s start attack" % (curr_time, host.IP()))
                            host.cmd("./runos/src/apps/ddos-defender/scripts/atckWithOpts.sh %s %s %s %s" 
                                     % (host.MAC(), host.IP(),2,send_delay))
                    for j in range(num_intervals) :
                        curr_time = monotonic() - start
                        if (curr_time+2 < atck_time+5) :
                            print("curr_time=%s :: %s start attack" % (curr_time, host.IP()))
                            host.cmd("./runos/src/apps/ddos-defender/scripts/atckWithOpts.sh %s %s %s %s" 
                                     % (host.MAC(), host.IP(),2,send_delay))
                        send_delay -= offset_delay
                    k+=1

                while curr_time < test_time+5:
                    curr_time = monotonic() - start
                    interval = (5 + test_time - curr_time) if (5 + test_time - curr_time) >=1 else 1
                    print("curr_time=%s :: %s start ping %s for %s sec" % (curr_time, host.IP(), ping_pair.IP(), interval))
                    host.cmd("./runos/src/apps/ddos-defender/scripts/png.sh %s %s" % (ping_pair.IP(),interval))
                    sleep(0.5)

                file_name = "atck_duration_" + str(i) + ".txt"
                handle = open(file_name, "w")
                handle.write("'%s' : [%s, %s]" % (net.get(hosts[i]).IP(), 5, 45))
                handle.close()
            else:

                ping_pair = net.get(hosts[i-1])
                curr_time = monotonic() - start
                interval = (5 - curr_time) if (5 - curr_time) >=1 else 1
                print("curr_time=%s :: %s start ping %s for %s sec" % (curr_time, host.IP(), ping_pair.IP(), interval))
                host.cmd("./runos/src/apps/ddos-defender/scripts/png.sh %s %s" % (ping_pair.IP(),interval))

                ping_pair = net.get(hosts[i-2])
                curr_time = monotonic() - start
                interval = (25 - curr_time) if (25 - curr_time) >=1 else 1
                print("curr_time=%s :: %s start ping %s for %s sec" % (curr_time, host.IP(), ping_pair.IP(), interval))
                host.cmd("./runos/src/apps/ddos-defender/scripts/png.sh %s %s" % (ping_pair.IP(),interval))

                ping_pair = net.get(hosts[i-3])
                curr_time = monotonic() - start
                interval = (test_time+5 - curr_time) if (test_time+5 - curr_time) >=1 else 1
                print("curr_time=%s :: %s start ping %s for %s sec" % (curr_time, host.IP(), ping_pair.IP(), interval))
                host.cmd("./runos/src/apps/ddos-defender/scripts/png.sh %s %s" % (ping_pair.IP(),interval))

            sys.exit(3)
        if pid > 0 :
            childs.append( pid )

    for p in childs :
        pid, status = os.wait()
    print('childs end')

    host = net.get(hosts[0])
    handleResult = open("runos/src/apps/ddos-defender/tests/infectedMACs.txt", "w")
    handleResult.write("{")
    for i in range(len(hosts)):
        if hosts[i] in inf_hosts:
            file_name = "atck_duration_" + str(i) + ".txt"
            handle = open(file_name, "r")
            result = handle.read()
            handleResult.write(result)
            if i < (len(hosts)-1):
                handleResult.write(", ")
            handle.close()
            cmnd = "sudo rm " + file_name
            host.cmd(cmnd)
    handleResult.write("}")
    handleResult.close()


    CLI(net)
    net.stop()


if __name__ == '__main__':
    # Tell mininet to print useful information
    setLogLevel('info')
    simpleTest()
