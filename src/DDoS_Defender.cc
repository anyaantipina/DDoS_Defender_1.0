#include "DDoS_Defender.hpp"
#include "PacketParser.hpp"

#include <algorithm>
#include <unistd.h>
#include <sys/types.h>
#include "sys/times.h"
#include "sys/vtimes.h"
#include <sstream>
#include <stdexcept>
#include <tins/ip.h>
#include <cmath>

static clock_t lastCPU, lastSysCPU, lastUserCPU;

static bool ATTACK, CLEAR;
static int omega;
static int tau, common_t, big_t;
static float alpha, threshold_low, threshold_hight;
static float cpu_util, threshold_cpu_util;
int current_time, sw_response_number;
int commonPNF;
uint64_t numberClearTables;

namespace runos {

REGISTER_APPLICATION(DDoS_Defender, {"controller", "host-manager", "switch-manager",  "link-discovery", "dhcp-server", ""})

std::string correct_ip_addr(std::string ip){
    std::vector<std::string> fragms;
    std::string fragm = "";
    for (char c : ip){
        if (c == '.'){
            fragms.push_back(fragm);
            fragm = "";
        }
        else {
            fragm += c;
        }
    }
    fragms.push_back(fragm);
    return fragms[3] + '.' + fragms[2] + '.' + fragms[1] + '.' + fragms[0];
}

float string_to_float(std::string s) {
    std::string::size_type pos = s.rfind(".");
    std::string x1 = s.substr(0, pos);
    std::string x2 = s.substr(pos+1, s.length()-pos-1);
    int y1 = 0;
    int y2 = 0;
    if (x1.length() != 0) {
        y1 = stoi(x1);
    }
    if (x2.length() != 0) {
        y2 = stoi(x2);
    }
    return (y1+y2*pow(0.1,x2.length()));
}

void init_cpu_util(){
    struct tms timeSample;

    lastCPU = times(&timeSample);
    lastSysCPU = timeSample.tms_stime;
    lastUserCPU = timeSample.tms_utime;
}

void DDoS_Defender::get_cpu_util(){
    struct tms timeSample;
    clock_t now;
    float percent;

    now = times(&timeSample);
    if (now <= lastCPU || timeSample.tms_stime < lastSysCPU ||
        timeSample.tms_utime < lastUserCPU){
        percent = -1.0;
    }
    else{
        percent = (timeSample.tms_stime - lastSysCPU) + (timeSample.tms_utime - lastUserCPU);
        percent /= (now - lastCPU);
        percent *= 100;
    }
    lastCPU = now;
    lastSysCPU = timeSample.tms_stime;
    lastUserCPU = timeSample.tms_utime;

    cpu_util = percent;
}

DDoS_Defender::BTinfo::BTinfo(ethaddr mac, ipv4addr ip, ipv4addr oldip, 
                                uint64_t dpid, uint32_t port, bool status=false, 
                                bool host=false): 
                MAC(mac), IP(ip), oldIP(oldip), DPID(dpid), PortNo(port), Status(status), isHost(host) {};


std::string DDoS_Defender::BTinfo::getStrMAC() {
    return boost::lexical_cast<std::string>(MAC);
}

std::string DDoS_Defender::BTinfo::getStrIP() {
    return boost::lexical_cast<std::string>(IP);
}

controlFilterModule::SWobj::SWobj(bool status=false, bool edge=false): Status(status), isEdge(edge) {};

bool controlFilterModule::SWobj::isAllPortsOff() {
    bool allOff = true;
    for (auto it : ports.trusted) {
        if (it.second == true) {
            allOff = false;
            break;
        }
    }
    for (auto it : ports.users) {
        if (it.second == true) {
            allOff = false;
            break;
        }
    }
    for (auto it : ports.unknown) {
        if (it.second == true) {
            allOff = false;
            break;
        }
    }
    return allOff;
}

collectStatsModule::statsPort::statsPort() {
    gamma = 0;
    gamma_per_tau = 0;
    drop = 0;
    diff_drop = 0;
    score = threshold_hight;
    PNF = commonPNF;
    type = USR;
}

std::string collectStatsModule::statsPort::whatType(){
    switch (type) {
        case USR : return "USR";
        case INF : return "INF";
        case AMB : return "AMB";
    }
    return "";
}

collectStatsModule::statsSW::statsSW() {
    beta = 0;
    lambda = 0;
    alpha = omega;
}

collectStatsModule::collectStatsModule() {
    isAlphaExceed = false;
    numberSW = 0;
    sumBeta = 0;
    sumLambda = 0;
}

DDoS_Defender::DDoS_Defender() {
    CFModPtr = std::make_unique<controlFilterModule>();
    CSModPtr = std::make_unique<collectStatsModule>();
}

void DDoS_Defender::onHostDiscovered(Host* dev) {
    //host_info host(dev->mac(), dev->ip(), dev->switchPort(), dev->switchID());
    //CFModPtr->hosts.push_back(host);
    if (dev->mac() != "00:00:00:00:00:00") {
        if (dev->ip() == "0.0.0.0") {
            BTinfo info(ethaddr(dev->mac()), convert("0.0.0.0").first, 
                        convert("0.0.0.0").first, dev->switchID(), dev->switchPort());
            BindingTable_.emplace(dev->mac(), info);
            auto it = CFModPtr->switches_.find(dev->switchID());
            if (it != CFModPtr->switches_.end()) {
                if (CFModPtr->switches_[dev->switchID()].Status == false) {
                    LOG(INFO) << "the message came from a switch " << dev->switchID() << " that is OFF";
                }
                auto itPort = it->second.ports.unknown.find(dev->switchPort());
                if (itPort != it->second.ports.unknown.end()) {
                    if (itPort->second == false) {
                        LOG(INFO) << "the message came from a switch " << dev->switchID() << " from port " 
                                        << dev->switchPort() << " that is OFF";
                    }
                }
                else {
                    itPort = it->second.ports.trusted.find(dev->switchPort());
                    if (itPort != it->second.ports.trusted.end()) {
                        LOG(INFO) << "the message from unknown IP came from a switch " << dev->switchID() << " from port " 
                                            << dev->switchPort() << " that is TRUSTED";
                    }
                    else {
                        itPort = it->second.ports.users.find(dev->switchPort());
                        if (itPort != it->second.ports.users.end()) {
                            LOG(INFO) << "the message from unknown IP came from a switch " << dev->switchID() << " from port " 
                                                << dev->switchPort() << " that is USERS";
                        }
                    }
                }
            }
            
        }
        
        else {
            BTinfo info(ethaddr(dev->mac()), convert(correct_ip_addr(dev->ip())).first,
                                convert(correct_ip_addr("0.0.0.0")).first, dev->switchID(), dev->switchPort(), true, true);
            BindingTable_.emplace(dev->mac(), info);
            auto it = CFModPtr->switches_.find(dev->switchID());
            if (it != CFModPtr->switches_.end()) {
                //LOG(INFO) << "NEW NODE " << dev->mac() << " : " 
                //            << convert(correct_ip_addr(dev->ip())).first << " IS HOST and ON";
                if (CFModPtr->switches_[dev->switchID()].Status == false) {
                    LOG(INFO) << "the message came from a switch " << dev->switchID() << " that is OFF";
                }
                auto itPort = it->second.ports.users.find(dev->switchPort());
                if (itPort != it->second.ports.users.end()) {
                    if (itPort->second == false) {
                        LOG(INFO) << "the message came from a switch " << dev->switchID() << " from port " 
                                        << dev->switchPort() << " that is OFF";
                    }
                }
                else {
                    itPort = it->second.ports.trusted.find(dev->switchPort());
                    if (itPort != it->second.ports.trusted.end()) {
                        if (itPort->second == false) {
                            LOG(INFO) << "the message came from a switch " << dev->switchID() << " from port " 
                                            << dev->switchPort() << " that is OFF";
                        }
                        CFModPtr->switches_[dev->switchID()].ports.users.emplace(dev->switchPort(), true);
                        CFModPtr->switches_[dev->switchID()].ports.trusted.erase(dev->switchPort());
                        std::string sw_port = boost::lexical_cast<std::string>(dev->switchID()) + 
                                                boost::lexical_cast<std::string>(dev->switchPort());
                        CFModPtr->sw_port_to_MAC.emplace(sw_port,dev->mac());

                        collectStatsModule::statsPort port;
                        CSModPtr->stats_[dev->switchID()].ports.emplace(dev->switchPort(), port);
                        //LOG(INFO) << "ON SWITCH " << dev->switchID() << " TRUSTED PORT " << dev->switchPort() << " COME USERS";
                    }
                    else {
                        itPort = it->second.ports.unknown.find(dev->switchPort());
                        if (itPort != it->second.ports.unknown.end()) {
                            if (itPort->second == false) {
                                LOG(INFO) << "the message came from a switch " << dev->switchID() << " from port " 
                                            << dev->switchPort() << " that is OFF";
                            }
                            CFModPtr->switches_[dev->switchID()].ports.users.emplace(dev->switchPort(),true);
                            CFModPtr->switches_[dev->switchID()].ports.unknown.erase(dev->switchPort());
                            std::string sw_port = boost::lexical_cast<std::string>(dev->switchID()) + 
                                                    boost::lexical_cast<std::string>(dev->switchPort());
                            CFModPtr->sw_port_to_MAC.emplace(sw_port,dev->mac());
                            collectStatsModule::statsPort port;
                            CSModPtr->stats_[dev->switchID()].ports.emplace(dev->switchPort(), port);
                            //LOG(INFO) << "ON SWITCH " << dev->switchID() << " UNKNOWN PORT " << dev->switchPort() << " COME USERS";
                        }
                    }
                }
                if (CFModPtr->switches_[dev->switchID()].isEdge == false) {
                    CFModPtr->switches_[dev->switchID()].isEdge = true;
                    //LOG(INFO) << "SWITCH " << dev->switchID() << " is EDGE";
                    CSModPtr->numberSW++;

                    collectStatsModule::statsSW ssw;
                    CSModPtr->stats_.emplace(dev->switchID(), ssw);
                    //LOG(INFO) << "NUMBER OF EDGE SWITCHES IS " << CSModPtr->numberSW;
                    CSModPtr->recount();
                }
            }
            else {
                LOG(INFO) << "the message came from a switch " << dev->switchID() << " that is not in switches_";
            }
            CFModPtr->add_filtered_flows(sender_, dev->mac(), correct_ip_addr(dev->ip()), dev->switchID(), dev->switchPort());
        }
    }
}

void DDoS_Defender::onAddrChanged(Client* dev) {
    std::string MAC = boost::lexical_cast<std::string>(dev->MAC);
    std::string newIP = (Tins::IPv4Address(htonl(dev->IP))).to_string();
    auto itBT = BindingTable_.find(MAC);
    if ((itBT != BindingTable_.end()) && (MAC != "00:00:00:00:00:00")) {
        if (itBT->second.IP != convert(newIP).first) { 
            //LOG(INFO) << "NODE " << MAC << " : " << newIP << "(" << itBT->second.getStrIP() << ") IS HOST and ON";
            auto it = CFModPtr->switches_.find(itBT->second.DPID);
            if (it != CFModPtr->switches_.end()) {
                if (CFModPtr->switches_[itBT->second.DPID].Status == false) {
                    LOG(INFO) << "the message came from a switch " << itBT->second.DPID << " that is OFF";
                }
                auto itPort = it->second.ports.users.find(itBT->second.PortNo);
                if (itPort != it->second.ports.users.end()) {
                    if (itPort->second == false) {
                        LOG(INFO) << "the message came from a switch " << itBT->second.DPID << " from port " 
                                        << itBT->second.PortNo << " that is OFF";
                    }
                }
                else {
                    itPort = it->second.ports.trusted.find(itBT->second.PortNo);
                    if (itPort != it->second.ports.trusted.end()) {
                        if (itPort->second == false) {
                            LOG(INFO) << "the message came from a switch " << itBT->second.DPID << " from port " 
                                            << itBT->second.PortNo << " that is OFF";
                        }
                        CFModPtr->switches_[itBT->second.DPID].ports.users.emplace(itBT->second.PortNo,true);
                        CFModPtr->switches_[itBT->second.DPID].ports.trusted.erase(itBT->second.PortNo);
                        std::string sw_port = boost::lexical_cast<std::string>(itBT->second.DPID) + 
                                                boost::lexical_cast<std::string>(itBT->second.PortNo);
                        CFModPtr->sw_port_to_MAC.emplace(sw_port,MAC);
                        collectStatsModule::statsPort port;
                        CSModPtr->stats_[itBT->second.DPID].ports.emplace(itBT->second.PortNo, port);
                        //LOG(INFO) << "ON SWITCH " << itBT->second.DPID << " TRUSTED PORT " << itBT->second.PortNo << " COME USERS";
                    }
                    else {
                        itPort = it->second.ports.unknown.find(itBT->second.PortNo);
                        if (itPort != it->second.ports.unknown.end()) {
                            if (itPort->second == false) {
                                LOG(INFO) <<  "the message came from a switch " << itBT->second.DPID << " from port " 
                                                << itBT->second.PortNo << " that is OFF";
                            }
                            CFModPtr->switches_[itBT->second.DPID].ports.users.emplace(itBT->second.PortNo,true);
                            CFModPtr->switches_[itBT->second.DPID].ports.unknown.erase(itBT->second.PortNo);
                            std::string sw_port = boost::lexical_cast<std::string>(itBT->second.DPID) + 
                                                    boost::lexical_cast<std::string>(itBT->second.PortNo);
                            CFModPtr->sw_port_to_MAC.emplace(sw_port,MAC);
                            collectStatsModule::statsPort port;
                            CSModPtr->stats_[itBT->second.DPID].ports.emplace(itBT->second.PortNo, port);
                            //LOG(INFO) << "ON SWITCH " << itBT->second.DPID << " UNKNOWN PORT " << itBT->second.PortNo << " COME USERS";
                        }
                    }
                }
                if (CFModPtr->switches_[itBT->second.DPID].isEdge == false) {
                    CFModPtr->switches_[itBT->second.DPID].isEdge = true;
                    //LOG(INFO) << "SWITCH " << itBT->second.DPID << " is EDGE";
                    CSModPtr->numberSW++;

                    collectStatsModule::statsSW ssw;
                    CSModPtr->stats_.emplace(itBT->second.DPID, ssw);
                    //LOG(INFO) << "NUMBER OF EDGE SWITCHES IS " << CSModPtr->numberSW;
                    CSModPtr->recount();
                }
            }
            else {
                LOG(INFO) << "the message came from a switch " << itBT->second.DPID << " that is not in switches_";
            }
            CFModPtr->delete_old_flows(sender_, MAC, itBT->second.getStrIP(), itBT->second.DPID, itBT->second.PortNo);
            CFModPtr->add_filtered_flows(sender_, MAC, newIP, itBT->second.DPID, itBT->second.PortNo);
            itBT->second.IP = convert(newIP).first;
            itBT->second.Status = true;
            itBT->second.isHost = true;
        }
    }
    else {
        LOG(INFO) << "the message came from host " << MAC << " that is not in BindindTable";
    }
}

void DDoS_Defender::onSwitchUp(SwitchPtr dev) {
    auto itSW = CFModPtr->switches_.find(dev->dpid());
    if (itSW != CFModPtr->switches_.end()) {
        if ((CFModPtr->switches_[dev->dpid()]).Status == false) {
            (CFModPtr->switches_[dev->dpid()]).Status = true;
            //LOG(INFO) << "SWITCH " << dev->dpid() << " UP";
            if (CFModPtr->switches_[dev->dpid()].isEdge == true) {
                CSModPtr->numberSW++;
                //LOG(INFO) << "NUMBER OF EDGE SWITCHES IS " << CSModPtr->numberSW;
                CSModPtr->recount();
            }
        }
    }
    else {
        controlFilterModule::SWobj sw(true,false);
        CFModPtr->switches_.emplace(dev->dpid(), sw);
        //LOG(INFO) << "SWITCH " << dev->dpid() << " UP";
    }
    if (BindingTable_.size() != 0) {
        for (auto it = BindingTable_.begin(); it != BindingTable_.end(); it++) {
            if (it->second.DPID == dev->dpid()) {
                it->second.Status = true;
            }
        }
    }
}

void DDoS_Defender::onSwitchDown(SwitchPtr dev) {
    auto itSW = CFModPtr->switches_.find(dev->dpid());
    if ((itSW != CFModPtr->switches_.end()) && itSW->second.Status) {
        itSW->second.Status = false;
        //LOG(INFO) << "SWITCH " << dev->dpid() << " DOWN";
        if (itSW->second.isEdge) {
            CSModPtr->numberSW--;
            CSModPtr->recount();
        }
    }
    else {
        LOG(INFO) << "the message came from a switch " << dev->dpid() << " that is not in switches_";
    }

    if (BindingTable_.size() != 0) {
        for (auto it = BindingTable_.begin(); it != BindingTable_.end(); it++) {
            if (it->second.DPID == dev->dpid()) {
                it->second.Status = false;
            }
        }
    }
}

void DDoS_Defender::onLinkUp(PortPtr dev) {
    auto itSW = CFModPtr->switches_.find(dev->switch_()->dpid());
    if (itSW != CFModPtr->switches_.end()) {
        auto itPort = itSW->second.ports.trusted.find(dev->number());
        if (itPort != itSW->second.ports.trusted.end()) {
            if (itSW->second.Status == false) {
                itSW->second.Status = true;
                //LOG(INFO) << "SWITCH " << dev->switch_()->dpid() << " UP";
                if (CFModPtr->switches_[dev->switch_()->dpid()].isEdge == true) {
                    CSModPtr->numberSW++;
                    //LOG(INFO) << "NUMBER OF EDGE SWITCHES IS " << CSModPtr->numberSW;
                    CSModPtr->recount();
                }
            }
            itPort->second = true;
            //LOG(INFO) << "ON SWITCH " << dev->switch_()->dpid() << " TRUSTED PORT " << dev->number() << " UP";
        }
        else {
            itPort = itSW->second.ports.users.find(dev->number());
            if (itPort != itSW->second.ports.users.end()) {
                if (itSW->second.Status == false) {
                    itSW->second.Status = true;
                    //LOG(INFO) << "SWITCH " << dev->switch_()->dpid() << " UP";
                    if (CFModPtr->switches_[dev->switch_()->dpid()].isEdge == true) {
                        CSModPtr->numberSW++;
                        //LOG(INFO) << "NUMBER OF EDGE SWITCHES IS " << CSModPtr->numberSW;
                        CSModPtr->recount();
                    }
                }
                itPort->second = true;
                //LOG(INFO) << "ON SWITCH " << dev->switch_()->dpid() << " USERS PORT " << dev->number() << " UP";   

            }
            else {
                itPort = itSW->second.ports.unknown.find(dev->number());
                if (itPort != itSW->second.ports.unknown.end()) {
                    itPort->second = true;
                }
                else {
                    itSW->second.ports.unknown.emplace(dev->number(),true);
                }
                if (itSW->second.Status == false) {
                    itSW->second.Status = true;
                    //LOG(INFO) << "SWITCH " << dev->switch_()->dpid() << " UP";
                    if (CFModPtr->switches_[dev->switch_()->dpid()].isEdge == true) {
                        CSModPtr->numberSW++;
                        //LOG(INFO) << "NUMBER OF EDGE SWITCHES IS " << CSModPtr->numberSW;
                        CSModPtr->recount();
                    }
                }
                //LOG(INFO) << "ON SWITCH " << dev->switch_()->dpid() << " UNKNOWN PORT " << dev->number() << " UP";
            }
        }
    }
    else {
        controlFilterModule::SWobj sw(true,false);
        sw.ports.unknown.emplace(dev->number(),true);
        CFModPtr->switches_.emplace(dev->switch_()->dpid(), sw);
        //LOG(INFO) << "SWITCH " << dev->switch_()->dpid() << " UP";
        //LOG(INFO) << "ON SWITCH " << dev->switch_()->dpid() << " UNKNOWN PORT " << dev->number() << " UP";
    }
}

void DDoS_Defender::onLinkDown(PortPtr dev) {
    auto itSW = CFModPtr->switches_.find(dev->switch_()->dpid());
    if (itSW != CFModPtr->switches_.end()) {
        auto itPort = itSW->second.ports.trusted.find(dev->number());
        if (itPort != itSW->second.ports.trusted.end()) {
            itPort->second = false;
            //LOG(INFO) << "ON SWITCH " << dev->switch_()->dpid() << " TRUSTED PORT " << dev->number() << " DOWN";
        }
        else {
            auto itPort = itSW->second.ports.users.find(dev->number());
            if (itPort != itSW->second.ports.users.end()) {
                itPort->second = false;
                std::string mac="",ip="";
                for (auto it : BindingTable_) {
                    if ((it.second.DPID == dev->switch_()->dpid()) && (it.second.PortNo == dev->number())) {
                        mac += it.second.getStrMAC(); 
                        ip += it.second.getStrIP();
                        break;
                    }
                }
                CFModPtr->delete_old_flows(sender_, mac, ip, dev->switch_()->dpid(), dev->number());
                //LOG(INFO) << "ON SWITCH " << dev->switch_()->dpid() << " USERS PORT " << dev->number() << " DOWN";
            }
            else {
                itPort = itSW->second.ports.unknown.find(dev->number());
                if (itPort != itSW->second.ports.unknown.end()) {
                    itPort->second = false;
                    //LOG(INFO) << "ON SWITCH " << dev->switch_()->dpid() << " UNKNOWN PORT " << dev->number() << " DOWN";
                }
                else {
                    LOG(INFO) << "the message came from a switch " << dev->switch_()->dpid() 
                                << " from port that is not in switch's ports";
                }
                
            }
        }

        if (itSW->second.isAllPortsOff() && itSW->second.Status) {
            itSW->second.Status = false;
            //LOG(INFO) << "SWITCH " << dev->switch_()->dpid() << " DOWN";
            if (itSW->second.isEdge) {
                CSModPtr->numberSW--;
                CSModPtr->recount();
            }
            if (BindingTable_.size() != 0) {
                for (auto it = BindingTable_.begin(); it != BindingTable_.end(); it++) {
                    if (it->second.DPID == dev->switch_()->dpid()) {
                        it->second.Status = false;
                    }
                }
            }
        }
    }
    else {
        LOG(INFO) << "the message came from a switch " << dev->switch_()->dpid() << " that is not in switches_";
    }

    std::string ss = boost::lexical_cast<std::string>(dev->switch_()->dpid()) + boost::lexical_cast<std::string>(dev->number());
    if (CFModPtr->sw_port_to_MAC.find(ss) != CFModPtr->sw_port_to_MAC.end())
        BindingTable_.find(CFModPtr->sw_port_to_MAC[ss])->second.Status = false;
}

void DDoS_Defender::onLinkDiscovered(switch_and_port from, switch_and_port to) {
    auto itSW = CFModPtr->switches_.find(from.dpid);
    if (itSW != CFModPtr->switches_.end()) {
        if (itSW->second.Status == false) {
            itSW->second.Status = true;
            //LOG(INFO) << "SWITCH " << from.dpid << " UP";
            if (CFModPtr->switches_[from.dpid].isEdge == true) {
                CSModPtr->numberSW++;
                //LOG(INFO) << "NUMBER OF EDGE SWITCHES IS " << CSModPtr->numberSW;
                CSModPtr->recount();
            }
        }
        auto itPort = itSW->second.ports.unknown.find(from.port);
        if (itPort != itSW->second.ports.unknown.end()) {
            CFModPtr->switches_[from.dpid].ports.trusted.emplace(from.port,true);
            CFModPtr->switches_[from.dpid].ports.unknown.erase(from.port);
            //LOG(INFO) << "ON SWITCH " << from.dpid << " UNKNOWN PORT " << from.port << " COME TRUSTED";
        }
        else {
            itPort = itSW->second.ports.users.find(from.port);
            if (itPort != itSW->second.ports.users.end()) {
                CFModPtr->switches_[from.dpid].ports.trusted.emplace(from.port,true);
                CFModPtr->switches_[from.dpid].ports.users.erase(from.port);
                //LOG(INFO) << "ON SWITCH " << from.dpid << " UNKNOWN PORT " << from.port << " COME TRUSTED";
            }
            else {
                itPort = itSW->second.ports.trusted.find(from.port);
                if (itPort != itSW->second.ports.trusted.end()) {
                    itPort->second = true;
                }
                else
                    CFModPtr->switches_[from.dpid].ports.trusted.emplace(from.port,true);
                //LOG(INFO) << "ON SWITCH " << from.dpid << " TRUSTED PORT " << from.port << " UP";
            }
        }
    }
    else {
        controlFilterModule::SWobj sw(true,false);
        sw.ports.trusted.emplace(from.port,true);
        CFModPtr->switches_.emplace(from.dpid, sw);
        //LOG(INFO) << "SWITCH " << from.dpid << " UP";
        //LOG(INFO) << "ON SWITCH " << from.dpid << " TRUSTED PORT " << from.port << " UP";
    } 

    itSW = CFModPtr->switches_.find(to.dpid);
    if (itSW != CFModPtr->switches_.end()) {
        if (itSW->second.Status == false) {
            itSW->second.Status = true;
            //LOG(INFO) << "SWITCH " << to.dpid << " UP";
            if (CFModPtr->switches_[to.dpid].isEdge == true) {
                CSModPtr->numberSW++;
                //LOG(INFO) << "NUMBER OF EDGE SWITCHES IS " << CSModPtr->numberSW;
                CSModPtr->recount();
            }
        }
        auto itPort = itSW->second.ports.unknown.find(to.port);
        if (itPort != itSW->second.ports.unknown.end()) {
            CFModPtr->switches_[to.dpid].ports.trusted.emplace(to.port,true);
            CFModPtr->switches_[to.dpid].ports.unknown.erase(to.port);
            //LOG(INFO) << "ON SWITCH " << to.dpid << " UNKNOWN PORT " << to.port << " COME TRUSTED";
        }
        else {
            itPort = itSW->second.ports.users.find(to.port);
            if (itPort != itSW->second.ports.users.end()) {
                CFModPtr->switches_[to.dpid].ports.trusted.emplace(to.port,true);
                CFModPtr->switches_[to.dpid].ports.users.erase(to.port);
                //LOG(INFO) << "ON SWITCH " << to.dpid << " UNKNOWN PORT " << to.port << " COME TRUSTED";
            }
            else {
                itPort = itSW->second.ports.trusted.find(to.port);
                if (itPort != itSW->second.ports.trusted.end()) {
                    itPort->second = true;
                }
                else
                    CFModPtr->switches_[to.dpid].ports.trusted.emplace(to.port,true);
                //LOG(INFO) << "ON SWITCH " << to.dpid << " TRUSTED PORT " << to.port << " UP";
            }
        }
    }
    else {
        controlFilterModule::SWobj sw(true,false);
        sw.ports.trusted.emplace(to.port,true);
        CFModPtr->switches_.emplace(to.dpid, sw);
        //LOG(INFO) << "SWITCH " << to.dpid << " UP";
        //LOG(INFO) << "ON SWITCH " << to.dpid << " TRUSTED PORT " << to.port << " UP";
    }
}

struct PortStatCount {
    uint64_t dpid;
    uint32_t port;
    int drop;
    int packets;
    int flows;
    bool from_LS;

    PortStatCount(uint64_t dpd=0, uint32_t prt=0, int dr=0, int pckt=0, int fls=0, bool fLS=false) : 
                        dpid(dpd), port(prt), drop(dr), packets(pckt), flows(fls), from_LS(fLS) {}
};


void DDoS_Defender::init(Loader *loader, const Config &rootConfig){

    LOG(INFO) << "";
    LOG(INFO) << "=====================";
    LOG(INFO) << "DDoS_Defender init start";        
    LOG(INFO) << "---------------------";

    auto config = config_cd(rootConfig, "ddos-defender");
    alpha = string_to_float(config_get(config, "alpha", "0.2").c_str());
    threshold_cpu_util = string_to_float(config_get(config, "TCU", "80.0").c_str());
    tau = config_get(config, "tau", 3);
    common_t = tau*3;
    big_t = common_t*3;
    omega = 100;
    sw_response_number = 0;
    commonPNF = 5.0;
    threshold_low = 1.0 / tau;
    threshold_hight = float(commonPNF) / tau;
    numberClearTables = 0;
    CLEAR = true;

    LOG(INFO) << "alpha = " << alpha;
    LOG(INFO) << "TCU = " << threshold_cpu_util;
    LOG(INFO) << "tau = " << tau;
    LOG(INFO) << "omega = " << omega;
    LOG(INFO) << "threshold_low = " << threshold_low;
    LOG(INFO) << "threshold_hight = " << threshold_hight;

    

    init_cpu_util();
    ATTACK = false;
    HostManager* host_manager_ = HostManager::get(loader);
    DhcpServer* dhcp_server_ = DhcpServer::get(loader);
    LinkDiscovery* link_discovery_ = dynamic_cast<LinkDiscovery*>(LinkDiscovery::get(loader));
    switch_manager_ = SwitchManager::get(loader);
    sender_ = OFMsgSender::get(loader);

    //ADD HOSTS
    QObject::connect(host_manager_, &HostManager::hostDiscovered, this, &DDoS_Defender::onHostDiscovered);

    //CHANGED IP
    QObject::connect(dhcp_server_, &DhcpServer::addrChanged, this, &DDoS_Defender::onAddrChanged);

    //CHANGE SWITCH STATUS
    QObject::connect(switch_manager_, &SwitchManager::switchUp, this, &DDoS_Defender::onSwitchUp);

    QObject::connect(switch_manager_, &SwitchManager::switchDown, this, &DDoS_Defender::onSwitchDown);
    
    //CHANGE PORT STATUS
    QObject::connect(switch_manager_, &SwitchManager::linkUp, this, &DDoS_Defender::onLinkUp);

    QObject::connect(switch_manager_, &SwitchManager::linkDown, this, &DDoS_Defender::onLinkDown);

    QObject::connect(link_discovery_, &LinkDiscovery::linkDiscovered, this, &DDoS_Defender::onLinkDiscovered);
  
    handler_ = Controller::get(loader)->register_handler(
    [this](of13::PacketIn& pi, OFConnectionPtr ofconn) -> bool
    {
        PacketParser pp(pi);
        runos::Packet& pkt(pp);

        const auto ofb_eth_type = oxm::eth_type(); // for optimization
        const auto ofb_ipv4_src = oxm::ipv4_src();
        const auto ofb_eth_src = oxm::eth_src();
        const auto ofb_in_port = oxm::in_port();
        const auto ofb_arp_spa = oxm::arp_spa();

        ipv4addr src_ip(convert("0.0.0.0").first);
        if (pkt.test(ofb_eth_type == 0x0800)) {
            src_ip = ipv4addr(pkt.load(ofb_ipv4_src));
        } else if (pkt.test(ofb_eth_type == 0x0806)) {
            src_ip = ipv4addr(pkt.load(ofb_arp_spa));
        }
        ethaddr src_mac = pkt.load(ofb_eth_src);
        uint32_t in_port = pkt.load(ofb_in_port);
        uint64_t dpid = ofconn->dpid();

        std::string str_mac = boost::lexical_cast<std::string>(src_mac);
        std::string str_ip = correct_ip_addr(boost::lexical_cast<std::string>(src_ip));
        auto itBT = BindingTable_.find(str_mac);
        if (itBT != BindingTable_.end()) {
            if (CSModPtr->stats_[itBT->second.DPID].ports.find(itBT->second.PortNo)
                != CSModPtr->stats_[itBT->second.DPID].ports.end()) {
                CSModPtr->stats_[itBT->second.DPID].ports[itBT->second.PortNo].gamma++;
                CSModPtr->stats_[itBT->second.DPID].ports[itBT->second.PortNo].gamma_per_tau++;
                CSModPtr->stats_[itBT->second.DPID].beta++;
                CSModPtr->stats_[itBT->second.DPID].lambda++;
                CSModPtr->sumBeta++;
                CSModPtr->sumLambda++;
            }
            if ((str_ip != "0.0.0.0") && (itBT->second.IP == convert("0.0.0.0").first)) { 
                CFModPtr->add_filtered_flows(sender_, str_mac, str_ip, itBT->second.DPID, itBT->second.PortNo);
                if (itBT->second.Status) {
                    //LOG(INFO) << "HOST " << str_mac << " : " << itBT->second.oldIP << " STATIC CHANGED IP to " << str_ip;
                }
                else {
                    itBT->second.Status = true;
                }
                itBT->second.IP = convert(str_ip).first;
                if (str_mac != "00:00:00:00:00:00") {
                    itBT->second.isHost = true;
                    //LOG(INFO) << "NODE " << str_mac << " : " << str_ip << " IS HOST and ON";

                }

                if (CFModPtr->switches_[itBT->second.DPID].Status == false) {
                    LOG(INFO) << "the message came from a switch " << itBT->second.DPID << " that is OFF";
                }
                auto it = CFModPtr->switches_.find(itBT->second.DPID);
                if (it != CFModPtr->switches_.end()) {
                    if (CFModPtr->switches_[itBT->second.DPID].Status == false) {
                        LOG(INFO) << "the message came from a switch " << itBT->second.DPID << " that is OFF";
                    }
                    auto itPort = it->second.ports.unknown.find(itBT->second.PortNo);
                    if (itPort != it->second.ports.unknown.end()) {
                        CFModPtr->switches_[itBT->second.DPID].ports.users.emplace(itBT->second.PortNo,true);
                        CFModPtr->switches_[itBT->second.DPID].ports.unknown.erase(itBT->second.PortNo);
                        std::string sw_port = boost::lexical_cast<std::string>(itBT->second.DPID) + 
                                                boost::lexical_cast<std::string>(itBT->second.PortNo);
                        CFModPtr->sw_port_to_MAC.emplace(sw_port,str_mac);
                        collectStatsModule::statsPort port;
                        CSModPtr->stats_[itBT->second.DPID].ports.emplace(itBT->second.PortNo, port);
                        //LOG(INFO) << "ON SWITCH " << itBT->second.DPID << " UNKNOWN PORT " << itBT->second.PortNo << " COME USERS";
                    }
                    else {
                        itPort = it->second.ports.trusted.find(itBT->second.PortNo);
                        if (itPort != it->second.ports.trusted.end()) {
                            if (itPort->second == false) {
                                //LOG(INFO) << "the message came from a switch " << itBT->second.DPID << " from port " 
                                //                << itBT->second.PortNo << " that is OFF";
                            }
                            CFModPtr->switches_[itBT->second.DPID].ports.users.emplace(itBT->second.PortNo, true);
                            CFModPtr->switches_[itBT->second.DPID].ports.trusted.erase(itBT->second.PortNo);
                            std::string sw_port = boost::lexical_cast<std::string>(itBT->second.DPID) + 
                                                    boost::lexical_cast<std::string>(itBT->second.PortNo);
                            CFModPtr->sw_port_to_MAC.emplace(sw_port,str_mac);
                            collectStatsModule::statsPort port;
                            CSModPtr->stats_[itBT->second.DPID].ports.emplace(itBT->second.PortNo, port);
                            //LOG(INFO) << "ON SWITCH " << itBT->second.DPID << " TRUSTED PORT " << itBT->second.PortNo << " COME USERS";
                        }
                    }
                    if (CFModPtr->switches_[itBT->second.DPID].isEdge == false) {
                        CFModPtr->switches_[itBT->second.DPID].isEdge = true;
                        //LOG(INFO) << "SWITCH " << itBT->second.DPID << " is EDGE";
                        CSModPtr->numberSW++;

                        collectStatsModule::statsSW ssw;
                        CSModPtr->stats_.emplace(itBT->second.DPID, ssw);
                        //LOG(INFO) << "NUMBER OF EDGE SWITCHES IS " << CSModPtr->numberSW;
                        CSModPtr->recount();
                    }
                }
                else {
                    LOG(INFO) << "the message came from a switch " << itBT->second.DPID << " that is not in switches_";
                }
                
            }
            else {
                if ((str_ip != "0.0.0.0") && (itBT->second.IP != convert(str_ip).first)) {
                    LOG(INFO) << "the message came from the host " << str_ip 
                                << " with different IP that is in the BindingTable " << itBT->second.IP;
                    if (itBT->second.oldIP == convert("0.0.0.0").first) {
                        CFModPtr->delete_old_flows(sender_, str_mac, itBT->second.getStrIP(), itBT->second.DPID, itBT->second.PortNo);
                        CFModPtr->add_filtered_flows(sender_, str_mac, str_ip, itBT->second.DPID, itBT->second.PortNo);
                        if (itBT->second.Status) {
                        //    LOG(INFO) << "HOST " << str_mac << " : " << itBT->second.IP << " STATIC CHANGED IP to " << str_ip;
                        }
                        else {
                            itBT->second.Status = true;
                        }
                        itBT->second.IP = convert(str_ip).first;
                        if (str_mac != "00:00:00:00:00:00") {
                            itBT->second.isHost = true;
                            //LOG(INFO) << "NODE " << str_mac << " : " << str_ip << " IS HOST and ON";

                        }

                    }           
                }
                else if ((str_ip != "0.0.0.0") && (itBT->second.IP == convert(str_ip).first) && (itBT->second.Status == false)) {
                    if (dpid != itBT->second.DPID) {
                        //LOG(INFO) << "HOST " << str_mac << " : " << str_ip << " MIGRATED from " << itBT->second.DPID 
                        //            << ":" << itBT->second.PortNo << " to " << dpid << ":" << in_port;
                        itBT->second.DPID = dpid;
                        itBT->second.PortNo = in_port;
                        itBT->second.Status = true;
                    }
                    else if (in_port != itBT->second.PortNo) {
                        //LOG(INFO) << "HOST " << str_mac << " : " << str_ip << " MIGRATED from " << itBT->second.PortNo 
                        //            << " to " << in_port;
                        itBT->second.PortNo = in_port;
                        itBT->second.Status = true;
                    }
                }
            }
            if (itBT->second.Status == false) {
                //LOG(INFO) << "HOST " << str_mac << " : " << str_ip << " is ON from " << itBT->second.PortNo 
                //            << " to " << in_port;
                itBT->second.Status = true;
            }
        }
        return false;
    }, -30);

    handler_flow_removed_ = Controller::get(loader)->register_handler(
    [this](of13::FlowRemoved& pi, OFConnectionPtr ofconn) -> bool
    {

        of13::Match match = pi.match();
        uint32_t in_port = 0;
        if (match.in_port()) in_port = match.in_port()->value();
        LOG(INFO) << "FLOW_REMOVED from SW=" << ofconn->dpid() << " : port=" << in_port 
                    << " : cookie=" << pi.cookie();
        std::string sw_port = boost::lexical_cast<std::string>(ofconn->dpid()) + 
                                boost::lexical_cast<std::string>(in_port);
        auto itMAC = CFModPtr->sw_port_to_MAC.find(sw_port);
        if ((itMAC != CFModPtr->sw_port_to_MAC.end()) && (pi.cookie() == 4)) {
            auto itBT = BindingTable_.find(itMAC->second);
            auto itST = CSModPtr->stats_.find(ofconn->dpid());
            if ((itST != CSModPtr->stats_.end()) && (itBT != BindingTable_.end())) {
                auto itPort = itST->second.ports.find(in_port);
                if ((itPort != itST->second.ports.end()) && (itPort->second.type == INF)) {
                    itPort->second.type = USR;
                    itPort->second.score = threshold_hight;
                    auto it = infectedMACs_.find(itMAC->first);
                    if (it != infectedMACs_.end()) infectedMACs_.erase(it);
                    LOG(INFO) << "INFECTED HOST " << itBT->second.getStrIP() << " COME USERS : score=" 
                        << itPort->second.score
                        << " : type=" << itPort->second.whatType();
                }
            }
        }
        return false;
    }, -30);

    //FLOW STATS REPLY
    handler_flow_stats_ = Controller::get(loader)->register_handler(
    [this](of13::MultipartReplyFlow pi, OFConnectionPtr ofconn) -> bool
    {
        sw_response_number++;
        uint64_t sw_id = ofconn->dpid();
        if (BindingTable_.size()) {
            std::unordered_map<std::string, PortStatCount> portStats;
            for (auto flow : pi.flow_stats()){
                of13::FlowStats *flow1 = static_cast<of13::FlowStats *>(&flow);
                of13::Match match = flow1->match();
                uint32_t in_port = 0;
                std::string eth_src = "";
                if (match.in_port()) in_port = match.in_port()->value();
                if (match.eth_src()) eth_src += match.eth_src()->value().to_string();
                //LOG(INFO) << "SW(" << sw_id << ") :: in_port=" << in_port 
                //                    << " : eth_src=" << eth_src
                //                    << " : flow_prior=" << flow1->priority()
                //                    << " : cookie=" << flow1->cookie();
                
                auto itBT = BindingTable_.find(eth_src);
                if (itBT != BindingTable_.end()) {
                    auto it = portStats.find(eth_src);
                    if (it != portStats.end()){
                        if (flow1->cookie() == 0x2) {
                            it->second.drop+=flow.packet_count();
                        }
                        else if (flow1->cookie() != 0x3) {
                            it->second.packets+=flow.packet_count();
                            it->second.flows++;
                            it->second.from_LS = (flow1->cookie() == 0x0) ? true : false;
                        }
                    }
                    else {
                        if (flow1->cookie() == 0x2) {
                            portStats.emplace(eth_src,PortStatCount(sw_id,in_port,flow.packet_count()));
                        }
                        else if (flow.cookie() != 0x3) {
                            bool from_LS = (flow1->cookie() == 0x0) ? true : false;
                            portStats.emplace(eth_src,PortStatCount(sw_id,in_port,0,flow.packet_count(),1,from_LS));
                        }
                    }
                }
                else if (flow1->cookie() == 0x4) {
                    std::string sw_port = boost::lexical_cast<std::string>(sw_id) + 
                                            boost::lexical_cast<std::string>(in_port);
                    auto itMAC = CFModPtr->sw_port_to_MAC.find(sw_port);
                    if (itMAC != (CFModPtr->sw_port_to_MAC).end()) {
                        auto it = portStats.find(itMAC->second);
                        if (it != portStats.end()) {
                            it->second.drop+=flow.packet_count();
                        }
                        else {
                            portStats.emplace(itMAC->second,PortStatCount(sw_id,in_port,flow.packet_count()));
                        }
                    }
                }
            }
            if (!portStats.size()) {
                auto itSW = CSModPtr->stats_.find(sw_id);
                for (auto itPort=itSW->second.ports.begin(); itPort != itSW->second.ports.end(); itPort++){
                    if (itPort->second.diff_drop || itPort->second.drop) {
                        itPort->second.diff_drop = 0;
                        itPort->second.drop = 0;
                    }
                    itPort->second.PNF = commonPNF;
                }
            }
            
            int diff = 0;
            bool clear_table = true;
            for (auto it : portStats) {
                if ((infectedMACs_.find(it.first)!=infectedMACs_.end()) && it.second.from_LS) clear_table = false;
                auto elemBT = BindingTable_.find(it.first);
                if ((elemBT != BindingTable_.end()) && (sw_id == elemBT->second.DPID))  {
                    auto elemST = CSModPtr->stats_[sw_id].ports.find(elemBT->second.PortNo);

                    //LOG(INFO) << "port(portStats)=" << elemBT->second.PortNo << " :: drop=" << it.second.drop
                    //            << " : packets=" << it.second.packets << " : flows=" << it.second.flows;
                    if (elemST != CSModPtr->stats_[sw_id].ports.end()) {
                        //LOG(INFO) << "port(stats_)=" << elemST->first << " :: drop=" << elemST->second.drop
                        //            << " : diff_drop=" << elemST->second.diff_drop;

                        if (it.second.drop > elemST->second.drop) 
                            diff = it.second.drop - elemST->second.drop;
                        else diff = 0;

                        if ((diff < 2*common_t) && (diff) && (elemST->second.type != INF)) {
                            CFModPtr->delete_old_flows(sender_, it.first, elemBT->second.getStrIP(), 
                                                                        sw_id,  elemBT->second.PortNo);
                            elemBT->second.oldIP = elemBT->second.IP;
                            elemBT->second.IP = convert("0.0.0.0").first;
                            LOG(INFO) << "response from SW=" << sw_id << ": HAVE SOME DROPPED PACKETS per interval(" << diff
                                        << ") FROM " << it.first << " : " << elemBT->second.oldIP;
                        }
                        else if (diff && (elemST->second.type != INF)) {
                            LOG(INFO) << "response from SW=" << sw_id << ": TOO MANY DROPPED PACKETS per interval(" << diff 
                                        << ") FROM " << it.first << " : " << elemBT->second.getStrIP();
                        }
                    
                        elemST->second.diff_drop = diff;
                        elemST->second.drop = it.second.drop;
                        elemST->second.PNF = (it.second.flows) ? float(it.second.packets) / it.second.flows : commonPNF;
                    }
                
                }
            }  
            if (clear_table && !CLEAR) numberClearTables++;  
            if ((numberClearTables == CSModPtr->stats_.size()) && !CLEAR) {
                CLEAR = true;
                LOG(INFO) << "!!!!!!!!!!!!!!!!!!END CLEAR TABLES!!!!!!!!!!!!!!!!!!!";
            }
        }
        //FOR TESTING
        
        /*if (!test_interval) {
            LOG(INFO) << "STATS FROM SWITCH ID " << sw_id;
            add_flow_statistic_from_switch(flow_stats, sw_id);
            bool done = true;
            for (auto it : switch_flow_test){
                if (!it.second.done) {
                    done = false;
                    break;
                }
            }
            if (done) {
                test_interval = true;
            }
        }
        else {
            test_interval = false;
        }*/
        
        //add_src_statistic_from_switch(flow_stats, sw_id);
        /*
        bool is_filled = true;
        sw_response[sw_id] = true;
        for (auto it : sw_response)
            if (it.second == false) {
                is_filled = false;
            }

        if (ATTACK) {
            check_src_criterion(sw_id);
            if (is_filled == true) {
                check_attack_end();
            }
        }*/
        return false;
    }, -30);

    LOG(INFO) << "----------------------------------";
    LOG(INFO) << "DDoS_Defender init finish its work";
    LOG(INFO) << "==================================";
}

void DDoS_Defender::startUp(Loader* ) {
    startTimer(tau*1000);
    current_time = 0;

}


void DDoS_Defender::timerEvent(QTimerEvent*) {
    current_time+=tau;
    get_cpu_util();
    bool isCommonInterval = (current_time % (common_t)) ? false : true;
    if(isCommonInterval && !ATTACK) {
        LOG(INFO) << "**********************************************";
        LOG(INFO) << "CURRENT TIME " << current_time;
        CFModPtr->printSwitches();
        LOG(INFO) << "----------------------------------------";
        CFModPtr->getFlowStats(sender_);
        CSModPtr->comparison();
        trackINFHosts();
        printBindingTable();
        LOG(INFO) << "**********************************************";
    }
    if (ATTACK) {
        CFModPtr->getFlowStats(sender_);
        checkScore();
    }

    if (sw_response_number >= CSModPtr->numberSW) {
        LOG(INFO) << "----------------------------------------";
        CSModPtr->printStats();
        LOG(INFO) << "----------------------------------------";
        sw_response_number = 0;
    }

    CSModPtr->clean();
}

void DDoS_Defender::checkScore(){
    float score = 0;
    bool is_attack_end = true;
    for (auto itSW = CSModPtr->stats_.begin(); itSW != CSModPtr->stats_.end(); itSW++) {
        for (auto itPort = itSW->second.ports.begin(); itPort != itSW->second.ports.end(); itPort++) {
            LOG(INFO) << "PORT(" << itPort->first << ") :: gamma_per_tau="
                        << itPort->second.gamma_per_tau << " : PNF="
                        << itPort->second.PNF << " : last_score=" 
                        << itPort->second.score;
            score = (itPort->second.gamma_per_tau) ? 
                        itPort->second.PNF / itPort->second.gamma_per_tau :
                        itPort->second.PNF;
            itPort->second.score = score;
            if (itPort->second.type != INF) {
                if (score <= threshold_low) {
                    score = score*(1-alpha) + itPort->second.score*alpha;
                    itPort->second.type = INF;
                    send_drop_flows(itSW->first,itPort->first);
                    std::string sw_port = boost::lexical_cast<std::string>(itSW->first) + 
                                            boost::lexical_cast<std::string>(itPort->first);
                    auto itMAC = CFModPtr->sw_port_to_MAC.find(sw_port);
                    if (itMAC != CFModPtr->sw_port_to_MAC.end()) {
                        infectedMACs_.insert(itMAC->second);
                    }
                }
                else {
                    if (score >= threshold_hight) {
                        score = score*(1-alpha) + itPort->second.score*alpha;
                        itPort->second.type = USR;
                    }
                    else { 
                        if (cpu_util > threshold_cpu_util) {
                            score = score*(1-alpha) + itPort->second.score*alpha;
                            itPort->second.type = INF;
                            send_drop_flows(itSW->first,itPort->first);
                            std::string sw_port = boost::lexical_cast<std::string>(itSW->first) + 
                                                    boost::lexical_cast<std::string>(itPort->first);
                            auto itMAC = CFModPtr->sw_port_to_MAC.find(sw_port);
                            if (itMAC != CFModPtr->sw_port_to_MAC.end()) {
                                infectedMACs_.insert(itMAC->second);
                            }
                        }
                        else {
                            score = score*(1-alpha) + itPort->second.score*alpha;
                            itPort->second.type = AMB;
                            is_attack_end = false;
                        }
                    }
                }
            }
        }
    }
    if (is_attack_end && (CSModPtr->sumBeta <= omega)) {
        ATTACK = !is_attack_end;
        LOG(INFO) << "!!!!!!!!!!!!!!!!!!!!!ATTACK END!!!!!!!!!!!!!!!!!!!!!!!!!!";
        numberClearTables = 0;
        CLEAR = false;
        clearTables();
    }
}

void DDoS_Defender::clearTables() {
    for (auto infMAC : infectedMACs_) {
        for (auto itSW : CSModPtr->stats_) {
            LOG(INFO) << "send delete flows to SW=" << itSW.first << " for MAC=" << infMAC;
            of13::FlowMod fm1, fm2;
            std::stringstream ss;
            fm1.command(of13::OFPFC_DELETE); fm2.command(of13::OFPFC_DELETE);
            fm1.table_id(of13::OFPTT_ALL); fm2.table_id(of13::OFPTT_ALL);
            fm1.priority(2); fm2.priority(2);
            fm1.cookie(0x0); fm2.cookie(0x0);
            fm1.cookie_mask(0); fm2.cookie_mask(0);
            fm1.idle_timeout(uint64_t(60)); fm2.idle_timeout(uint64_t(60)); 
            fm1.hard_timeout(uint64_t(1800)); fm2.hard_timeout(uint64_t(1800)); 

            ethaddr eth_src(infMAC);
            ss.str(std::string());
            ss.clear();
            ss << eth_src;
            fm1.add_oxm_field(new of13::EthSrc{fluid_msg::EthAddress(ss.str())});
            fm2.add_oxm_field(new of13::EthSrc{fluid_msg::EthAddress (ss.str())});

            fm1.out_port(of13::OFPP_ANY); fm2.out_port(of13::OFPP_ANY);
            fm1.out_group(of13::OFPP_ANY); fm2.out_group(of13::OFPP_ANY);

            sender_->send(itSW.first, fm1);
            sender_->send(itSW.first, fm2);
        }
    }
}

void DDoS_Defender::trackINFHosts(){
    if (CSModPtr->stats_.size()) {
        for (auto itSW=CSModPtr->stats_.begin(); itSW!=CSModPtr->stats_.end(); itSW++){
            if (itSW->second.beta < itSW->second.alpha) {
                for (auto itPort = itSW->second.ports.begin(); itPort!=itSW->second.ports.end(); itPort++) {
                    if (itPort->second.type == INF) {
                        std::string sw_port = boost::lexical_cast<std::string>(itSW->first) + 
                                                boost::lexical_cast<std::string>(itPort->first);
                        auto itMAC = CFModPtr->sw_port_to_MAC.find(sw_port);
                        auto itBT = BindingTable_.find(itMAC->second);
                        itPort->second.type = USR;
                        itPort->second.score = threshold_hight;
                        auto it = infectedMACs_.find(itMAC->first);
                        if (it != infectedMACs_.end()) infectedMACs_.erase(it);
                        LOG(INFO) << "INFECTED HOST " << itBT->second.getStrIP() << " COME USERS : score=" 
                            << itPort->second.score
                            << " : type=" << itPort->second.whatType();
                    }
                }
            }
        }
    }
}

void collectStatsModule::comparison(){
    if (stats_.size()) {
        bool isRecountAlpha = false;
        for (auto itSW=stats_.begin(); itSW!=stats_.end(); itSW++){
            for (auto itPort : itSW->second.ports) {
                if (itPort.second.whatType() == "INF") {
                    itSW->second.beta += itPort.second.diff_drop;
                    itSW->second.lambda += itPort.second.diff_drop;
                    sumLambda += itPort.second.diff_drop;
                }
            }
            if ((itSW->second.beta > itSW->second.alpha) && (sumBeta > omega)) {
                ATTACK = true;
                LOG(INFO) << "!!!!!!!!!!!!!!!!!!!!!ATTACK BEGIN!!!!!!!!!!!!!!!!!!!!!!!!!!";
                break;
            }
            else if ((itSW->second.beta > itSW->second.alpha) && (sumBeta <= omega)) {
                isRecountAlpha = true;
            }
        }
        if (isRecountAlpha && sumLambda) {
            isAlphaExceed = true;
            for (auto itSW=stats_.begin(); itSW!=stats_.end(); itSW++){
                itSW->second.alpha = trunc((omega*itSW->second.lambda)/sumLambda);
            }
        }
    }
}

void collectStatsModule::recount(){
    if (isAlphaExceed && sumLambda) {
        for (auto itSW=stats_.begin(); itSW!=stats_.end(); itSW++){
            itSW->second.alpha = trunc((omega*itSW->second.lambda)/sumLambda);
        }
    }
    else if (numberSW) {
        for (auto itSW=stats_.begin(); itSW!=stats_.end(); itSW++){
            itSW->second.alpha = trunc(omega/numberSW);
        }
    }
}

void collectStatsModule::clean(){
    if (stats_.size()) {
        for (auto itSW=stats_.begin(); itSW!=stats_.end(); itSW++){
            for (auto itPort=itSW->second.ports.begin(); itPort!=itSW->second.ports.end(); itPort++) {
                itPort->second.gamma_per_tau = 0;
            }
        }
        bool isBigInterval = (current_time % (big_t)) ? false : true;
        bool isCommonInterval = (current_time % (common_t)) ? false : true;
        if (isBigInterval) sumLambda = 0;
        if (isCommonInterval) {
            sumBeta = 0;
            for (auto itSW=stats_.begin(); itSW!=stats_.end(); itSW++){
                itSW->second.beta = 0;
                if (isBigInterval) itSW->second.lambda = 0;
                for (auto itPort=itSW->second.ports.begin(); itPort!=itSW->second.ports.end(); itPort++) {
                    itPort->second.gamma = 0;
                }
            }
        }
    }
}

void controlFilterModule::add_filtered_flows(OFMsgSender* sender, 
                                                    std::string MAC, std::string IP, uint64_t sw_id, uint32_t port) {
    //DROP ACTIONS
    uint16_t priority = 2;

    of13::FlowMod fm1, fm2;
    fm1.command(of13::OFPFC_ADD); fm2.command(of13::OFPFC_ADD);
    fm1.xid(0); fm2.xid(0);
    fm1.buffer_id(OFP_NO_BUFFER); fm2.buffer_id(OFP_NO_BUFFER);
    fm1.table_id(0); fm2.table_id(0);
    fm1.priority(priority); fm2.priority(priority);
    fm1.cookie(0x2); fm2.cookie(0x2);
    fm1.idle_timeout(0); fm2.idle_timeout(0);
    fm1.hard_timeout(0); fm2.hard_timeout(0);
    fm1.flags( of13::OFPFF_SEND_FLOW_REM ); fm2.flags( of13::OFPFF_SEND_FLOW_REM );
    fm1.add_oxm_field(new of13::EthType(0x0800)); fm2.add_oxm_field(new of13::EthType(0x0806));
    fm1.add_oxm_field(new of13::InPort(port)); fm2.add_oxm_field(new of13::InPort(port));
    sender->send(sw_id, fm1); sender->send(sw_id, fm2);
    
    
    //GOTOTABLE ACTIONS
    priority = 3;

    of13::FlowMod fm3, fm4;
    std::stringstream ss;
    fm3.command(of13::OFPFC_ADD); fm4.command(of13::OFPFC_ADD);
    fm3.xid(3); fm4.xid(3);
    fm3.buffer_id(OFP_NO_BUFFER); fm4.buffer_id(OFP_NO_BUFFER);
    fm3.table_id(0); fm4.table_id(0);
    fm3.priority(priority); fm4.priority(priority);
    fm3.cookie(0x3); fm4.cookie(0x3);
    fm3.idle_timeout(uint64_t(0)); fm4.idle_timeout(uint64_t(0));
    fm3.hard_timeout(uint64_t(0)); fm4.hard_timeout(uint64_t(0));
    fm3.flags( of13::OFPFF_SEND_FLOW_REM ); fm4.flags( of13::OFPFF_SEND_FLOW_REM );
    fm3.add_oxm_field(new of13::EthType(0x0800)); fm4.add_oxm_field(new of13::EthType(0x0806));
    fm3.add_oxm_field(new of13::InPort(port)); fm4.add_oxm_field(new of13::InPort(port));

    ethaddr eth_src(MAC);
    ss.str(std::string());
    ss.clear();
    ss << eth_src;
    fm3.add_oxm_field(new of13::EthSrc{fluid_msg::EthAddress(ss.str())});
    fm4.add_oxm_field(new of13::EthSrc{fluid_msg::EthAddress (ss.str())});

    ipv4addr ipv4_src(convert(IP).first);
    ss.str(std::string());
    ss.clear();
    ss << ipv4_src;
    fm3.add_oxm_field(new of13::IPv4Src{fluid_msg::IPAddress (ss.str())});

    of13::GoToTable go_to_table(1);
    fm3.add_instruction(go_to_table);
    fm4.add_instruction(go_to_table);
    sender->send(sw_id, fm3);
    sender->send(sw_id, fm4);
}

void controlFilterModule::delete_old_flows(OFMsgSender* sender, 
                                                    std::string MAC, std::string IP, uint64_t sw_id, uint32_t port) {                                                
    //DROP ACTIONS
    uint16_t priority = 2;

    of13::FlowMod fm1, fm2;
    fm1.command(of13::OFPFC_DELETE); fm2.command(of13::OFPFC_DELETE);
    fm1.xid(2); fm2.xid(2);
    fm1.buffer_id(OFP_NO_BUFFER); fm2.buffer_id(OFP_NO_BUFFER);
    fm1.table_id(0); fm2.table_id(0);
    fm1.priority(priority); fm2.priority(priority);
    fm1.cookie(0x2); fm2.cookie(0x2);
    fm1.idle_timeout(0); fm2.idle_timeout(0);
    fm1.hard_timeout(0); fm2.hard_timeout(0);
    fm1.flags( of13::OFPFF_SEND_FLOW_REM );
    fm2.flags( of13::OFPFF_SEND_FLOW_REM );
    fm1.add_oxm_field(new of13::EthType(0x0800));
    fm2.add_oxm_field(new of13::EthType(0x0806));
    fm1.add_oxm_field(new of13::InPort(port));
    fm2.add_oxm_field(new of13::InPort(port));
    sender->send(sw_id, fm1);
    sender->send(sw_id, fm2);
    

    //GOTOTABLE ACTIONS
    priority = 3;

    of13::FlowMod fm3, fm4;
    std::stringstream ss;
    fm3.command(of13::OFPFC_DELETE); fm4.command(of13::OFPFC_DELETE);
    fm3.xid(3); fm4.xid(3);
    fm3.buffer_id(OFP_NO_BUFFER); fm4.buffer_id(OFP_NO_BUFFER);
    fm3.table_id(0); fm4.table_id(0);
    fm3.priority(priority); fm4.priority(priority);
    fm3.cookie(0x3); fm4.cookie(0x3);
    fm3.idle_timeout(uint64_t(0)); fm4.idle_timeout(uint64_t(0));
    fm3.hard_timeout(uint64_t(0)); fm4.hard_timeout(uint64_t(0));
    fm3.flags( of13::OFPFF_SEND_FLOW_REM ); fm4.flags( of13::OFPFF_SEND_FLOW_REM );
    fm3.add_oxm_field(new of13::EthType(0x0800)); fm4.add_oxm_field(new of13::EthType(0x0806));
    fm3.add_oxm_field(new of13::InPort(port)); fm4.add_oxm_field(new of13::InPort(port));

    ethaddr eth_src(MAC);
    ss.str(std::string());
    ss.clear();
    ss << eth_src;
    fm3.add_oxm_field(new of13::EthSrc{fluid_msg::EthAddress(ss.str())});
    fm4.add_oxm_field(new of13::EthSrc{fluid_msg::EthAddress (ss.str())});

    ipv4addr ipv4_src(convert(IP).first);
    ss.str(std::string());
    ss.clear();
    ss << ipv4_src;
    fm3.add_oxm_field(new of13::IPv4Src{fluid_msg::IPAddress (ss.str())});

    of13::GoToTable go_to_table(1);
    fm3.add_instruction(go_to_table);
    fm4.add_instruction(go_to_table);
    sender->send(sw_id, fm3);
    sender->send(sw_id, fm4);
}

void DDoS_Defender::send_drop_flows(uint64_t sw_id, uint32_t port) {
    LOG(INFO) << "SEND DROP FLOWS to SW=" << sw_id << " : port=" << port;
    of13::FlowMod fm1, fm2;
    fm1.command(of13::OFPFC_ADD); fm2.command(of13::OFPFC_ADD);
    fm1.xid(0); fm2.xid(0);
    fm1.buffer_id(OFP_NO_BUFFER); fm2.buffer_id(OFP_NO_BUFFER);
    fm1.table_id(0); fm2.table_id(0);
    fm1.priority(4); fm2.priority(4);
    fm1.cookie(0x4); fm2.cookie(0x4);
    fm1.idle_timeout(60); fm2.idle_timeout(60);
    fm1.hard_timeout(0); fm2.hard_timeout(0);
    fm1.flags( of13::OFPFF_SEND_FLOW_REM );
    fm2.flags( of13::OFPFF_SEND_FLOW_REM );
    fm1.add_oxm_field(new of13::EthType(0x0800));
    fm2.add_oxm_field(new of13::EthType(0x0806));
    fm1.add_oxm_field(new of13::InPort(port));
    fm2.add_oxm_field(new of13::InPort(port));
    sender_->send(sw_id, fm1);
    sender_->send(sw_id, fm2);
}

void controlFilterModule::getFlowStats(OFMsgSender* sender){
    for (auto it : switches_){
        if (it.second.isEdge == true) {
            of13::MultipartRequestFlow mprf;
            mprf.table_id(of13::OFPTT_ALL);
            mprf.out_port(of13::OFPP_ANY);
            mprf.out_group(of13::OFPG_ANY);
            mprf.cookie(0x0);
            mprf.cookie_mask(0x0);
            mprf.flags(0);
            sender->send(it.first, mprf);
        }
    }
    /*bool is_filled = true;
    for (auto it : sw_response) {
        if (it.second == false) {
            is_filled = false;
            break;
        }
    }
    if (is_filled == true){
        for (auto it = sw_response.begin(); it != sw_response.end(); it++) {
            it->second = false;
        }
    }*/
}

void DDoS_Defender::printBindingTable(){
    LOG(INFO) << "BINDING TABLE (size = " << BindingTable_.size() << ") :";
    for (auto it : BindingTable_) {
        LOG(INFO) << it.first << " : " << it.second.getStrIP() << " : dpid=" 
                    << it.second.DPID << " : port=" << it.second.PortNo << " : status=" 
                    << it.second.Status << " : isHost=" << it.second.isHost;
    }
}

void controlFilterModule::printSwitches(){
    LOG(INFO) << "SWITCHES (size = " << switches_.size() << ") :";
    for (auto it : switches_) {
        LOG(INFO) << it.first << " : status=" << it.second.Status << " : isEdge=" << it.second.isEdge;
        std::string user_ports = "user_ports (size = " + boost::lexical_cast<std::string>(it.second.ports.users.size()) + ") : ";
        for (auto itPort : it.second.ports.users) {
            user_ports += boost::lexical_cast<std::string>(itPort.first) + ":" 
                        + boost::lexical_cast<std::string>(itPort.second) + ", ";
        }
        LOG(INFO) << user_ports;

        std::string trusted_ports = "trusted_ports (size = " + boost::lexical_cast<std::string>(it.second.ports.trusted.size()) + ") : ";
        for (auto itPort : it.second.ports.trusted) {
            trusted_ports += boost::lexical_cast<std::string>(itPort.first) + ":" 
                            + boost::lexical_cast<std::string>(itPort.second) + ", ";
        }
        LOG(INFO) << trusted_ports;

        std::string unknown_ports = "unknown_ports (size = " + boost::lexical_cast<std::string>(it.second.ports.unknown.size()) + ") : ";
        for (auto itPort : it.second.ports.unknown) {
            unknown_ports += boost::lexical_cast<std::string>(itPort.first) + ":" 
                            + boost::lexical_cast<std::string>(itPort.second) + ", ";
        }
        LOG(INFO) << unknown_ports;
    }
}

void collectStatsModule::printStats(){
    LOG(INFO) << "STATS (size = " << stats_.size() << ") :";
    for (auto itSW : stats_) {
        LOG(INFO) << "SW=" << itSW.first << " :: ports : ";
        for (auto itPort : itSW.second.ports) {
            LOG(INFO) << itPort.first << " :: gamma=" << itPort.second.gamma 
                        << " : gamma_per_tau=" << itPort.second.gamma_per_tau
                        << " : drop=" << itPort.second.drop
                        << " : diff_drop=" << itPort.second.diff_drop 
                        << " : PNF=" << itPort.second.PNF
                        << " : score=" << itPort.second.score 
                        << " : type=" << itPort.second.whatType();
        }
        LOG(INFO) << "beta=" << itSW.second.beta << " : lambda=" << itSW.second.lambda << " : alpha=" << itSW.second.alpha;
    }
    LOG(INFO) << "numberSW=" << numberSW << " : sumBeta=" << sumBeta << " : sumLambda=" << sumLambda;
}

}