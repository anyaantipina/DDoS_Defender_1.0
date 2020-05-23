import sys

print("input tau:")
tau = eval(input())
numSwitches = 4

handle = open("/home/anna/runos/src/apps/ddos-defender/tests/infoForFPandFN.txt", "r")
l = [line.strip() for line in handle]
handle.close()

packetIns = eval(l[0])
packetDrops = eval(l[1])

if ("0.0.0.0" in packetIns) or ("0.0.0.0" in packetDrops):
    print("please, repeate experiment, smth went wrong (the IP address 0.0.0.0 can't be host's IP)")
    sys.exit(0)

handle = open("/home/anna/runos/src/apps/ddos-defender/tests/infectedMACs.txt", "r")
l = [line.strip() for line in handle]
handle.close()

infectedMACs = eval(l[0])
processedMACs = {}
for mac in packetIns:
    if mac in infectedMACs:
        startIND = int((infectedMACs[mac][0]) / tau)
        endIND = round((infectedMACs[mac][1]) / tau)
        print(mac, startIND, endIND)
        packetInsUSR = 0
        packetDropsUSR = 0
        packetInsINF = 0
        packetDropsINF = 0
        i = 0
        while (i < startIND):
            packetInsUSR += packetIns[mac][i] if (packetIns[mac][i] >= 0) else 0
            if (i < len(packetDrops[mac])):
                packetDropsUSR += packetDrops[mac][i] if (packetDrops[mac][i] >= 0) else 0
            i+=1
        
        correct = 1 if tau<3 else 0
        while (i < (endIND + correct)):
            packetInsINF += int(packetIns[mac][i] / numSwitches) if (packetIns[mac][i] >= 0) else 0
            if (i < len(packetDrops[mac])):
                packetDropsINF += packetDrops[mac][i] if (packetDrops[mac][i] >= 0) else 0
            i+=1

        while (i < len(packetIns[mac])):
            packetInsUSR += packetIns[mac][i] if (packetIns[mac][i] >= 0) else 0
            if (i < len(packetDrops[mac])):
                packetDropsUSR += packetDrops[mac][i] if (packetDrops[mac][i] >= 0) else 0
            i+=1

        print("%s packetInsUSR=%s packetDropsUSR=%s packetInsINF=%s packetDropsINF=%s" %
              (mac, packetInsUSR, packetDropsUSR, packetInsINF,packetDropsINF))

        processedMACs[mac] = {'packetInsUSR' : packetInsUSR,
                                'packetDropsUSR' : packetDropsUSR,
                                'packetInsINF' : packetInsINF,
                                'packetDropsINF' : packetDropsINF}
    else:
        packetInsUSR = 0
        packetDropsUSR = 0
        for i in range(len(packetIns[mac])):
            packetInsUSR += packetIns[mac][i] if (packetIns[mac][i] >= 0) else 0
            if (i < len(packetDrops[mac])):
                packetDropsUSR += packetDrops[mac][i] if (packetDrops[mac][i] >= 0) else 0
        print("%s packetInsUSR=%s packetDropsUSR=%s" %
              (mac, packetInsUSR, packetDropsUSR))

        processedMACs[mac] = {'packetInsUSR' : packetInsUSR,
                                'packetDropsUSR' : packetDropsUSR,}

print(processedMACs)


sumPacketInsUSR=0
sumPacketDropsUSR=0
sumPacketInsINF=0
sumPacketDropsINF=0
for mac in processedMACs:
    sumPacketInsUSR += processedMACs[mac]['packetInsUSR']
    sumPacketDropsUSR += processedMACs[mac]['packetDropsUSR']
    if 'packetInsINF' in processedMACs[mac] :
        sumPacketInsINF += processedMACs[mac]['packetInsINF']
        sumPacketDropsINF += processedMACs[mac]['packetDropsINF']

#print("sumUnprocessedPacketInsUSR=%s sumPacketInsUSR=%s sumPacketInsINF=%s sumPacketOutsINF=%s" %
      #(sumUnprocessedPacketInsUSR,sumPacketInsUSR,sumPacketInsINF,sumPacketOutsINF))
FP = (sumPacketDropsUSR / (sumPacketInsUSR + sumPacketDropsUSR)) if ((sumPacketInsUSR + sumPacketDropsUSR) > 0) else 0
FN = (sumPacketInsINF / (sumPacketInsINF + sumPacketDropsINF)) if ((sumPacketInsINF + sumPacketDropsINF) > 0) else 0

print("FP=%s, FN=%s" % (FP, FN))
