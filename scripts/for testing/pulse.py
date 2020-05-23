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
    print("packets per second during attack:")
    num_packets_atck = eval(input())
    print("packets per second during waiting:")
    num_packets_wait = eval(input())
    print("attack period duration:")
    atck_period_time = eval(input())
    print("wait period duration:")
    wait_period_time = eval(input())
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

    print(inf_hosts)

    atck_capacity_per_sec_for_host = num_packets_atck / len(inf_hosts)
    wait_capacity_per_sec_for_host = num_packets_wait / len(inf_hosts)
    num_intervals = atck_time / (atck_period_time + wait_period_time)
    send_delay_atck = round(1000/atck_capacity_per_sec_for_host)
    send_delay_wait = round(1000/wait_capacity_per_sec_for_host)

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

                curr_time = monotonic() - start
                sleep_time = 5 - curr_time
                if sleep_time > 0:
                    sleep(sleep_time)
                j = 1
                send_delay=0
                while j <= num_intervals :
                    curr_time = monotonic() - start
                    print("curr_time=%s :: %s wait attack" % (curr_time, host.IP()))
                    host.cmd("./runos/src/apps/ddos-defender/scripts/atckWithOpts.sh %s %s %s %s" 
                                % (host.MAC(), host.IP(),wait_period_time,send_delay_wait))
                    curr_time = monotonic() - start
                    print("curr_time=%s :: %s start attack" % (curr_time, host.IP()))
                    host.cmd("./runos/src/apps/ddos-defender/scripts/atckWithOpts.sh %s %s %s %s" 
                                % (host.MAC(), host.IP(),atck_period_time,send_delay_atck))
                    j+=1

                while curr_time < test_time+5:
                    curr_time = monotonic() - start
                    interval = (5 + test_time - curr_time) if (5 + test_time - curr_time) >=1 else 1
                    print("curr_time=%s :: %s start ping %s for %s sec" % (curr_time, host.IP(), ping_pair.IP(), interval))
                    host.cmd("./runos/src/apps/ddos-defender/scripts/png.sh %s %s" % (ping_pair.IP(),interval))
                    sleep(0.5)

                file_name = "atck_duration_" + str(i) + ".txt"
                handle = open(file_name, "w")
                handle.write("'%s' : [%s, %s]" % (net.get(hosts[i]).IP(), 5, num_intervals*(atck_period_time+wait_period_time)+5))
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
