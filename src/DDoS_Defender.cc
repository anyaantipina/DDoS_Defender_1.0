#include "DDoS_Defender.hpp"
#include "PacketParser.hpp"
#include "Recovery.hpp"

#include <algorithm>
#include <unistd.h>
#include <sys/types.h>
#include "sys/times.h"
#include "sys/vtimes.h"
#include <sstream>
#include <stdexcept>
#include <tins/ip.h>
#include <cmath>
#include <fstream>

static clock_t lastCPU, lastSysCPU, lastUserCPU;

static bool ATTACK, CLEAR;
static int omega;
static int tau, common_t, big_t;
static float alpha, threshold_low, threshold_hight;
static float cpu_util, threshold_cpu_util;
int current_time, sw_response_number;
int commonPNF;
uint numberClearSW;
bool isPacketsAmountSaved, computeFP_FN, startLogInfoForFPFN, computeTableUsage, appEnabled, logEnabled;
int testDuration, currentTestTime;

namespace runos {

REGISTER_APPLICATION(DDoS_Defender, {"controller", "host-manager", "switch-manager", 
                                        "link-discovery", "dhcp-server", "recovery-manager", "database-connector", ""})

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

nlohmann::json controlFilterModule::SWobj::to_json() {
    nlohmann::json ret = nlohmann::json::object();
    auto jdump1 = nlohmann::json::array();
    auto jdump2 = nlohmann::json::array();
    auto jdump3 = nlohmann::json::array();
    for (auto port : ports.users) {
        nlohmann::json j = nlohmann::json::object();
        j["port"] = port.first;
        j["status"] = port.second;
        jdump1.push_back(j);
    }
    for (auto port : ports.trusted) {
        nlohmann::json j = nlohmann::json::object();
        j["port"] = port.first;
        j["status"] = port.second;
        jdump2.push_back(j);
    }
    for (auto port : ports.unknown) {
        nlohmann::json j = nlohmann::json::object();
        j["port"] = port.first;
        j["status"] = port.second;
        jdump2.push_back(j);
    }
    ret["users"] = jdump1;
    ret["trusted"] = jdump2;
    ret["unknown"] = jdump3;
    ret["Status"] = Status;
    ret["isEdge"] = isEdge;
    return ret;
}

void controlFilterModule::save_switches_to_database(DatabaseConnector* dbc_) {
    if (!dbc_) return;
    //LOG(INFO) << "save_switches_to_database";
    if (switches_.size()) {
        auto jdump = nlohmann::json::array();
        for (auto sw : switches_) {
            nlohmann::json j = nlohmann::json::object(); 
            j["DPID"] = sw.first;
            j["info"] = sw.second.to_json();
            jdump.push_back(j);
        }
        dbc_->putSValue("ddos-defender", "switches", jdump.dump());
    }
}

void controlFilterModule::load_switches_from_database(DatabaseConnector* dbc_) {
    if (!dbc_) return;
    //LOG(INFO) << "load_switches_from_database";
    auto switches = dbc_->getSValue("ddos-defender", "switches");
    if (switches.empty()) return;
    auto switches_json = nlohmann::json::parse(switches);
    switches_.clear();
    for (const auto& elem_sw_json : switches_json) {
        SWobj elemSW;
        elemSW.Status = elem_sw_json["info"]["Status"];
        elemSW.isEdge = elem_sw_json["info"]["isEdge"];
        for (const auto& elem_port_json : elem_sw_json["info"]["users"]) {
            elemSW.ports.users.emplace(elem_port_json["port"],elem_port_json["status"]);
        }
        for (const auto& elem_port_json : elem_sw_json["info"]["trusted"]) {
            elemSW.ports.trusted.emplace(elem_port_json["port"],elem_port_json["status"]);
        }
        for (const auto& elem_port_json : elem_sw_json["info"]["unknown"]) {
            elemSW.ports.unknown.emplace(elem_port_json["port"],elem_port_json["status"]);
        }
        switches_.emplace(elem_sw_json["DPID"], elemSW);
    }
}

int controlFilterModule::getNumUpSwitches() {
    int number=0;
    for (auto it : switches_) {
        if (it.second.Status) number++;
    }
    return number;
}

collectStatsModule::statsPort::statsPort
    (int gpt=0, int dr=0, int ddr=0, int dr0x4=0, int ddr0x4=0, 
        float sc=threshold_hight, float pnf=commonPNF, bool isch=false,std::string t="USR") :
                                gamma_per_tau(gpt), drop(dr), diff_drop(ddr),drop_0x4(dr0x4), 
                                diff_drop_0x4(ddr0x4), score(sc), PNF(pnf), isCheck(isch) {
    if (t == "USR") type=USR;
    if (t == "INF") type=INF;
    if (t == "AMB") type=AMB;
}

std::string collectStatsModule::statsPort::whatType(){
    switch (type) {
        case USR : return "USR";
        case INF : return "INF";
        case AMB : return "AMB";
    }
    return "";
}

void collectStatsModule::save_stats_to_database(DatabaseConnector* dbc_) {
    if (!dbc_) return;
    //LOG(INFO) << "save_stats_to_database";
    if (stats_.size()) {
        auto jdump = nlohmann::json::array();
        for (auto sw : stats_) {
            nlohmann::json j = nlohmann::json::object();
            j["DPID"] = sw.first;
            j["beta"] = sw.second.beta;
            j["betaInf"] = sw.second.betaInf;
            j["alpha"] = sw.second.alpha;
            j["lambda"] = sw.second.lambda;
            auto jdump2 = nlohmann::json::array();
            for (auto port : sw.second.ports) {
                nlohmann::json j2 = nlohmann::json::object();
                j2["port"] = port.first;
                j2["gamma_per_tau"] = port.second.gamma_per_tau;
                j2["drop"] = port.second.drop;
                j2["diff_drop"] = port.second.diff_drop;
                j2["drop_0x4"] = port.second.drop_0x4;
                j2["diff_drop_0x4"] = port.second.diff_drop_0x4;
                j2["PNF"] = port.second.PNF;
                j2["score"] = port.second.score;
                j2["isCheck"] = port.second.isCheck;
                j2["type"] = port.second.whatType();
                jdump2.push_back(j2);
            }
            j["ports"] = jdump2;
            jdump.push_back(j);
        }
        nlohmann::json j = nlohmann::json::object();
        j["isAlphaExceed"] = isAlphaExceed;
        j["numberSW"] = numberSW;
        j["sumBeta"] = sumBeta;
        j["sumLambda"] = sumLambda;
        j["switches"] = jdump.dump();
        dbc_->putSValue("ddos-defender", "stats", j.dump());
    }
}

void collectStatsModule::load_stats_from_database(DatabaseConnector* dbc_) {
    if (!dbc_) return;
    //LOG(INFO) << "load_stats_from_database";
    auto stats = dbc_->getSValue("ddos-defender", "stats");
    if (stats.empty()) return;
    auto stats_json = nlohmann::json::parse(stats);
    isAlphaExceed = stats_json["isAlphaExceed"];
    numberSW = stats_json["numberSW"];
    sumBeta = stats_json["sumBeta"];
    sumLambda = stats_json["sumLambda"];
    stats_.clear();
    std::string switches = stats_json["switches"];
    auto switches_json = nlohmann::json::parse(switches);
    for (const auto& elem_sw_json : switches_json) {
        statsSW elemSW;
        elemSW.beta = elem_sw_json["beta"];
        elemSW.betaInf = elem_sw_json["betaInf"];
        elemSW.alpha = elem_sw_json["alpha"];
        elemSW.lambda = elem_sw_json["lambda"];
        auto ports = elem_sw_json["ports"];
        for (const auto& elem_port_json : ports) {
            statsPort elemPort(elem_port_json["gamma_per_tau"],
                                elem_port_json["drop"], elem_port_json["diff_drop"],
                                elem_port_json["drop_0x4"], elem_port_json["diff_drop_0x4"],
                                elem_port_json["score"], elem_port_json["PNF"],
                                elem_port_json["isCheck"], elem_port_json["type"]);
            elemSW.ports.emplace(elem_port_json["port"], elemPort);
        }
        stats_.emplace(elem_sw_json["DPID"], elemSW);
    }
}

collectStatsModule::statsSW::statsSW() {
    beta = 0;
    betaInf = 0;
    lambda = 0;
    alpha = omega;
}

collectStatsModule::collectStatsModule() {
    isAlphaExceed = false;
    numberSW = 0;
    sumBeta = 0;
    sumLambda = 0;
}

nlohmann::json DDoS_Defender::BTinfo::to_json() {
    nlohmann::json ret = nlohmann::json::object();
    ret["MAC"] = getStrMAC();
    ret["IP"] = getStrIP();
    ret["oldIP"] = boost::lexical_cast<std::string>(oldIP);
    ret["DPID"] = DPID;
    ret["PortNo"] = PortNo;
    ret["Status"] = Status;
    ret["isHost"] = isHost;
    return ret;
}

void DDoS_Defender::save_BT_to_database() {
    if (!db_connector_) return;
    //LOG(INFO) << "save_BT_to_database";
    if (BindingTable_.size()) {
        auto jdump = nlohmann::json::array();
        for (auto itBT : BindingTable_) {
            jdump.push_back(itBT.second.to_json());
        }
        db_connector_->putSValue("ddos-defender", "binding-table", jdump.dump());
    }
}

void DDoS_Defender::load_BT_from_database() {
    if (!db_connector_) return;
    //LOG(INFO) << "load_BT_from_database";
    auto BT = db_connector_->getSValue("ddos-defender", "binding-table");
    if (BT.empty()) return;
    auto BT_json = nlohmann::json::parse(BT);
    BindingTable_.clear();
    for (const auto& elem_BT_json : BT_json) {
        std::string MAC = elem_BT_json["MAC"], IP = elem_BT_json["IP"], oldIP = elem_BT_json["oldIP"];
        uint64_t DPID = elem_BT_json["DPID"];
        uint32_t PortNo = elem_BT_json["PortNo"];
        bool Status = elem_BT_json["Status"], isHost = elem_BT_json["isHost"];
        BTinfo elem(ethaddr(MAC), ipv4addr(convert(IP).first), ipv4addr(convert(oldIP).first), 
                    DPID,PortNo, Status, isHost);
        BindingTable_.emplace(MAC, elem);
    }

    CFModPtr->sw_port_to_MAC.clear();
    for (auto itBT : BindingTable_) {
        std::string sw_port = boost::lexical_cast<std::string>(itBT.second.DPID) + 
                                boost::lexical_cast<std::string>(itBT.second.PortNo);
        CFModPtr->sw_port_to_MAC.emplace(sw_port, itBT.first);
    }
    infectedMACs_.clear();
    for (auto sw : CSModPtr->stats_) {
        for (auto port : sw.second.ports) {
            if (port.second.whatType() == "INF") {
                std::string sw_port = boost::lexical_cast<std::string>(sw.first) + 
                                    boost::lexical_cast<std::string>(port.first);
                auto itMAC = CFModPtr->sw_port_to_MAC.find(sw_port);
                if (itMAC != CFModPtr->sw_port_to_MAC.end())                   
                    infectedMACs_.emplace(itMAC->first);
            }
        }
        
    }
}

void DDoS_Defender::clear_database()
{
    if (!db_connector_) return;
    //LOG(INFO) << "clear database";
    db_connector_->delPrefix("DDoS_Defender");
}

void DDoS_Defender::onRecovery() {
    CFModPtr->load_switches_from_database(db_connector_);
    CSModPtr->load_stats_from_database(db_connector_);
    load_BT_from_database();
}

void DDoS_Defender::onPrimary() {
    clear_database();
}

DDoS_Defender::DDoS_Defender() {
    CFModPtr = std::make_unique<controlFilterModule>();
    CSModPtr = std::make_unique<collectStatsModule>();
}

void DDoS_Defender::onHostDiscovered(Host* dev) {
    startLogInfoForFPFN = true;
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

                    threshold_low = ( CFModPtr->getNumUpSwitches() > 0 ) ? 
                                    1.0 / (tau*(CFModPtr->getNumUpSwitches()*2)) : 1.0 / tau;
                    threshold_hight = float(commonPNF) / (tau*(CFModPtr->getNumUpSwitches()+1));
                    LOG(INFO) << "TL=" << threshold_low << " TH=" << threshold_hight;

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

                    threshold_low = ( CFModPtr->getNumUpSwitches() > 0 ) ? 
                                    1.0 / (tau*(CFModPtr->getNumUpSwitches()*2)) : 1.0 / tau;
                    threshold_hight = float(commonPNF) / (tau*(CFModPtr->getNumUpSwitches()+1));
                    LOG(INFO) << "TL=" << threshold_low << " TH=" << threshold_hight;

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
            delete_all_flows(MAC);
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
                threshold_low = ( CFModPtr->getNumUpSwitches() > 0 ) ? 
                                1.0 / (tau*(CFModPtr->getNumUpSwitches()*2)) : 1.0 / tau;
                    threshold_hight = float(commonPNF) / (tau*(CFModPtr->getNumUpSwitches()+1));
                    LOG(INFO) << "TL=" << threshold_low << " TH=" << threshold_hight;
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
            threshold_low = ( CFModPtr->getNumUpSwitches() > 0 ) ?
                            1.0 / (tau*(CFModPtr->getNumUpSwitches()*2)) : 1.0 / tau;
            threshold_hight = float(commonPNF) / (tau*(CFModPtr->getNumUpSwitches()+1));
            LOG(INFO) << "TL=" << threshold_low << " TH=" << threshold_hight;
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

                    threshold_low = ( CFModPtr->getNumUpSwitches() > 0 ) ? 
                                    1.0 / (tau*(CFModPtr->getNumUpSwitches()*2)) : 1.0 / tau;
                    threshold_hight = float(commonPNF) / (tau*(CFModPtr->getNumUpSwitches()+1));
                    LOG(INFO) << "TL=" << threshold_low << " TH=" << threshold_hight;

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

                        threshold_low = ( CFModPtr->getNumUpSwitches() > 0 ) ? 
                                        1.0 / (tau*(CFModPtr->getNumUpSwitches()*2)) : 1.0 / tau;
                        threshold_hight = float(commonPNF) / (tau*(CFModPtr->getNumUpSwitches()+1));
                        LOG(INFO) << "TL=" << threshold_low << " TH=" << threshold_hight;
                        
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

                        threshold_low = ( CFModPtr->getNumUpSwitches() > 0 ) ? 
                                        1.0 / (tau*(CFModPtr->getNumUpSwitches()*2)) : 1.0 / tau;
                        threshold_hight = float(commonPNF) / (tau*(CFModPtr->getNumUpSwitches()+1));
                        LOG(INFO) << "TL=" << threshold_low << " TH=" << threshold_hight;

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
                delete_all_flows(mac);
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
                threshold_low = ( CFModPtr->getNumUpSwitches() > 0 ) ? 
                                1.0 / (tau*(CFModPtr->getNumUpSwitches()*2)) : 1.0 / tau;
                threshold_hight = float(commonPNF) / (tau*(CFModPtr->getNumUpSwitches()+1));
                LOG(INFO) << "TL=" << threshold_low << " TH=" << threshold_hight;
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
    if (CFModPtr->sw_port_to_MAC.find(ss) != CFModPtr->sw_port_to_MAC.end()) {
        auto itBT = BindingTable_.find(CFModPtr->sw_port_to_MAC[ss]);
        if (itBT != BindingTable_.end()) {
            itBT->second.Status = false;
            CFModPtr->delete_old_flows(sender_, itBT->second.getStrMAC(), 
                        itBT->second.getStrIP(), itBT->second.DPID, itBT->second.PortNo);
            delete_all_flows(itBT->second.getStrMAC());
        }
    } 
}

void DDoS_Defender::onLinkDiscovered(switch_and_port from, switch_and_port to) {
    auto itSW = CFModPtr->switches_.find(from.dpid);
    if (itSW != CFModPtr->switches_.end()) {
        if (itSW->second.Status == false) {
            itSW->second.Status = true;
            //LOG(INFO) << "SWITCH " << from.dpid << " UP";
            if (CFModPtr->switches_[from.dpid].isEdge == true) {
                CSModPtr->numberSW++;
                threshold_low = ( CFModPtr->getNumUpSwitches() > 0 ) ? 
                                1.0 / (tau*(CFModPtr->getNumUpSwitches()*2)) : 1.0 / tau;
                threshold_hight = float(commonPNF) / (tau*(CFModPtr->getNumUpSwitches()+1));
                LOG(INFO) << "TL=" << threshold_low << " TH=" << threshold_hight;
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
                threshold_low = ( CFModPtr->getNumUpSwitches() > 0 ) ? 
                                1.0 / (tau*(CFModPtr->getNumUpSwitches()*2)) : 1.0 / tau;
                threshold_hight = float(commonPNF) / (tau*(CFModPtr->getNumUpSwitches()+1));
                LOG(INFO) << "TL=" << threshold_low << " TH=" << threshold_hight;
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
    int drop_0x4;

    PortStatCount(uint64_t dpd=0, uint32_t prt=0, int dr=0, int pckt=0, int fls=0, 
                        bool fLS=false, int dr0x4=0) : 
                        dpid(dpd), port(prt), drop(dr), packets(pckt), flows(fls), 
                        from_LS(fLS), drop_0x4(dr0x4){}
};

//for testing
//----------------------------------- 

void DDoS_Defender::checkTableUsage(std::unordered_map<std::string,int> testStats) {
    int infNum = 0, usrNum = 0;
    for (auto mac : testStats) {
        if (infectedMACs_.find(mac.first) != infectedMACs_.end()) {
            infNum+=mac.second;
        }
        else usrNum+=mac.second;
    }
    float infPerc = ((infNum + usrNum) > 0) ? float(infNum) / (infNum + usrNum) : 0;
    LOG(INFO) << "usrNum=" << usrNum << " : infNum=" << infNum << " : infPerc=" << infPerc;
}
//-----------------------------------


void DDoS_Defender::init(Loader *loader, const Config &rootConfig){

    LOG(INFO) << "";
    LOG(INFO) << "=====================";
    LOG(INFO) << "DDoS_Defender init start";        
    LOG(INFO) << "---------------------";

    auto config = config_cd(rootConfig, "ddos-defender");
    alpha = string_to_float(config_get(config, "alpha", "0.2").c_str());
    threshold_cpu_util = string_to_float(config_get(config, "TCU", "80.0").c_str());
    tau = config_get(config, "tau", 3);
    int numForCommon = config_get(config, "k", 3);
    int numForBig = 3;
    testDuration = 60;
    omega = 400;
    common_t = tau*numForCommon;
    big_t = common_t*numForBig;
    sw_response_number = 0;
    commonPNF = 5.0;
    threshold_low = 1.0 / (tau);
    threshold_hight = float(commonPNF) / (tau);
    numberClearSW = 0;
    isPacketsAmountSaved = false;
    computeTableUsage  = config_get(config, "computeTableUsage", false);
    computeFP_FN = config_get(config, "computeFP_FN", false);
    appEnabled  = config_get(config, "appEnabled", true);
    logEnabled  = config_get(config, "logEnabled", false);
    startLogInfoForFPFN = false;
    currentTestTime = -tau;
    CLEAR = true;

    LOG(INFO) << "alpha = " << alpha;
    LOG(INFO) << "TCU = " << threshold_cpu_util;
    LOG(INFO) << "tau = " << tau;
    LOG(INFO) << "omega = " << omega;
    LOG(INFO) << "threshold_low = " << threshold_low;
    LOG(INFO) << "threshold_hight = " << threshold_hight;
    LOG(INFO) << "computeTableUsage = " << computeTableUsage;
    LOG(INFO) << "computeFP_FN = " << computeFP_FN;
    LOG(INFO) << "appEnabled = " << appEnabled;
    LOG(INFO) << "logEnabled = " << logEnabled;

    

    init_cpu_util();
    ATTACK = false;
    HostManager* host_manager_ = HostManager::get(loader);
    DhcpServer* dhcp_server_ = DhcpServer::get(loader);
    LinkDiscovery* link_discovery_ = dynamic_cast<LinkDiscovery*>(LinkDiscovery::get(loader));
    switch_manager_ = SwitchManager::get(loader);
    sender_ = OFMsgSender::get(loader);
    db_connector_ = DatabaseConnector::get(loader);
    RecoveryManager* recovery = RecoveryManager::get(loader);

    //RECOVERY
    QObject::connect(recovery, &RecoveryManager::signalRecovery, this, &DDoS_Defender::onRecovery);
    
    QObject::connect(recovery, &RecoveryManager::signalSetupPrimaryMode, this, &DDoS_Defender::onPrimary);

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
                if (pkt.test(ofb_eth_type == 0x0800))  {
                    if (packetIns_.find(str_mac) != packetIns_.end()){
                        int size = packetIns_[str_mac].size();
                        if (size) packetIns_[str_mac][size-1] += (packetIns_[str_mac][size-1] != -1) ? 1 : 2;
                    }
                    else {
                        std::vector<int> elem;
                        int size = (currentTestTime) ? currentTestTime/tau : 1;
                        for (auto i = 0; i < size; i++) {
                            elem.push_back(0);
                        }
                        elem.push_back(1);
                        packetIns_.emplace(str_mac,std::move(elem));
                    }
                }
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
                        threshold_low = ( CFModPtr->getNumUpSwitches() > 0 ) ? 
                                        1.0 / (tau*(CFModPtr->getNumUpSwitches()*2)) : 1.0 / tau;
                        threshold_hight = float(commonPNF) / (tau*(CFModPtr->getNumUpSwitches()+1));
                        LOG(INFO) << "TL=" << threshold_low << " TH=" << threshold_hight;

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
                    //LOG(INFO) << "the message came from the host " << str_ip 
                    //            << " with different IP that is in the BindingTable " << itBT->second.IP;
                    if (itBT->second.oldIP == convert("0.0.0.0").first) {
                        CFModPtr->delete_old_flows(sender_, str_mac, itBT->second.getStrIP(), 
                                                    itBT->second.DPID, itBT->second.PortNo);
                        delete_all_flows(str_mac);
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
                    CFModPtr->delete_old_flows(sender_, str_mac, str_ip, itBT->second.DPID, itBT->second.PortNo);
                    delete_all_flows(str_mac);
                    CFModPtr->add_filtered_flows(sender_, str_mac, str_ip, dpid, in_port);
                    if (dpid != itBT->second.DPID) {
                        LOG(INFO) << "HOST " << str_mac << " : " << str_ip << " MIGRATED from " << itBT->second.DPID 
                                    << ":" << itBT->second.PortNo << " to " << dpid << ":" << in_port;
                        itBT->second.DPID = dpid;
                        itBT->second.PortNo = in_port;
                        itBT->second.Status = true;
                    }
                    else if (in_port != itBT->second.PortNo) {
                        LOG(INFO) << "HOST " << str_mac << " : " << str_ip << " MIGRATED from " << itBT->second.PortNo 
                                    << " to " << in_port;
                        itBT->second.PortNo = in_port;
                        itBT->second.Status = true;
                    }
                    auto it = CFModPtr->switches_.find(itBT->second.DPID);
                    if (it != CFModPtr->switches_.end()) {
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
                    }
                    else {
                        LOG(INFO) << "the message came from a switch " << itBT->second.DPID << " that is not in switches_";
                    }
                }
            }
        }
        return false;
    }, -30);

    if (appEnabled) {
        handler_flow_removed_ = Controller::get(loader)->register_handler(
        [this](of13::FlowRemoved& pi, OFConnectionPtr ofconn) -> bool
        {
            of13::Match match = pi.match();
            uint32_t in_port = 0;
            if (match.in_port()) in_port = match.in_port()->value();
            uint8_t reason = pi.reason();
            std::string sw_port = boost::lexical_cast<std::string>(ofconn->dpid()) + 
                                    boost::lexical_cast<std::string>(in_port);
            auto itMAC = CFModPtr->sw_port_to_MAC.find(sw_port);
            if ((itMAC != CFModPtr->sw_port_to_MAC.end()) && (pi.cookie() == 4) && (reason == of13::OFPRR_IDLE_TIMEOUT)) {
                auto itBT = BindingTable_.find(itMAC->second);
                auto itST = CSModPtr->stats_.find(ofconn->dpid());
                if ((itST != CSModPtr->stats_.end()) && (itBT != BindingTable_.end())) {
                    auto itPort = itST->second.ports.find(in_port);
                    if ((itPort != itST->second.ports.end()) && (itPort->second.type == INF)) {
                        itPort->second.type = USR;
                        itPort->second.score = threshold_hight;
                        auto it = infectedMACs_.find(itMAC->first);
                        if (it != infectedMACs_.end()) infectedMACs_.erase(it);
                        delete_drop_flows(itST->first, itPort->first);
                        LOG(INFO) << "flow_removed => infected host mac=" << itMAC->second << " : ip=" << itBT->second.getStrIP() << " come USERS";
                    }
                }
            }
            return false;
        }, -30);
    }

    //FLOW STATS REPLY
    handler_flow_stats_ = Controller::get(loader)->register_handler(
    [this](of13::MultipartReplyFlow pi, OFConnectionPtr ofconn) -> bool
    {
        sw_response_number++;
        uint64_t sw_id = ofconn->dpid();
        if (BindingTable_.size()) {
            std::unordered_map<std::string, PortStatCount> portStats;
            std::unordered_map<std::string, int> testStats;
            for (auto flow : pi.flow_stats()){
                of13::FlowStats *flow1 = static_cast<of13::FlowStats *>(&flow);
                of13::Match match = flow1->match();
                uint32_t in_port = 0;
                std::string eth_src = "";
                if (match.in_port()) in_port = match.in_port()->value();
                if (match.eth_src()) eth_src += match.eth_src()->value().to_string();
                
                auto itBT = BindingTable_.find(eth_src);
                if (itBT != BindingTable_.end()) {
                    auto it = portStats.find(eth_src);
                    //for testing
                    //-----------------------------------
                    if (computeTableUsage) {
                        auto testIT = testStats.find(eth_src);
                        if (testIT != testStats.end()) testIT->second++;
                        else testStats.emplace(eth_src,1);
                    }
                    //-----------------------------------

                    if (it != portStats.end()){
                        if ((flow1->cookie() == 0x2) || (flow1->cookie() == 0x4)){
                            if (flow1->cookie() == 0x2)
                                it->second.drop+=flow.packet_count();
                            else 
                                it->second.drop_0x4+=flow.packet_count();
                        }
                        else if (flow1->cookie() != 0x3) {
                            it->second.packets+=flow.packet_count();
                            it->second.flows++;
                            it->second.from_LS = (flow1->cookie() == 0x0) ? true : false;
                        }
                    }
                    else {
                        if ((flow1->cookie() == 0x2) || (flow1->cookie() == 0x4)) {
                            if (flow1->cookie() == 0x2)
                                portStats.emplace(eth_src,PortStatCount(sw_id,in_port,flow.packet_count()));
                            else
                                portStats.emplace(eth_src,PortStatCount(sw_id,in_port,0,0,1,false,flow.packet_count()));
                        }
                        else if (flow.cookie() != 0x3) {
                            bool from_LS = (flow1->cookie() == 0x0) ? true : false;
                            portStats.emplace(eth_src,PortStatCount(sw_id,in_port,0,flow.packet_count(),1,from_LS));
                        }
                    }
                }
                else {
                    //for testing
                    //-----------------------------------
                    if (computeTableUsage) {
                        std::string sw_port = boost::lexical_cast<std::string>(sw_id) + 
                                                    boost::lexical_cast<std::string>(in_port);
                        auto itMAC = CFModPtr->sw_port_to_MAC.find(sw_port);
                        if (itMAC != CFModPtr->sw_port_to_MAC.end()) {
                            auto testIT = testStats.find(itMAC->second);
                            if (testIT != testStats.end()) testIT->second++;
                            else testStats.emplace(eth_src,1);
                        }
                    }
                    //-----------------------------------

                    if ((flow1->cookie() == 0x4) || (flow1->cookie() == 0x2)) {
                        std::string sw_port = boost::lexical_cast<std::string>(sw_id) + 
                                                boost::lexical_cast<std::string>(in_port);
                        auto itMAC = CFModPtr->sw_port_to_MAC.find(sw_port);
                        if (itMAC != (CFModPtr->sw_port_to_MAC).end()) {
                            auto it = portStats.find(itMAC->second);
                            if (it != portStats.end()) {
                                if (flow1->cookie() == 0x2)
                                    it->second.drop+=flow.packet_count();
                                else
                                    it->second.drop_0x4+=flow.packet_count();
                            }
                            else {
                                if (flow1->cookie() == 0x2)
                                    portStats.emplace(itMAC->second,PortStatCount(sw_id,in_port,flow.packet_count()));
                                else
                                    portStats.emplace(itMAC->second,PortStatCount(sw_id,in_port,0,0,1,false,flow.packet_count()));
                            }
                        }
                    }
                }
            }
            if (!portStats.size()) {
                auto itSW = CSModPtr->stats_.find(sw_id);
                for (auto itPort=itSW->second.ports.begin(); itPort != itSW->second.ports.end(); itPort++){
                    if (itPort->second.diff_drop || itPort->second.drop) {
                        itPort->second.diff_drop = 0;
                    }
                    itPort->second.PNF = commonPNF;
                }
            }
            int diff = 0;
            int diff_0x4 = 0;
            bool clear_table = true;
            
            //for testing
            //-----------------------------------
            if (computeTableUsage) {
                LOG(INFO) << "testStats from switch=" << sw_id << " ::";
                checkTableUsage(testStats);
            }
            //-----------------------------------

            for (auto it : portStats) {
                if ((infectedMACs_.find(it.first)!=infectedMACs_.end()) && it.second.from_LS) clear_table = false;
                auto elemBT = BindingTable_.find(it.first);
                if ((elemBT != BindingTable_.end()) && (sw_id == elemBT->second.DPID))  {
                    auto elemST = CSModPtr->stats_[sw_id].ports.find(elemBT->second.PortNo);

                    //LOG(INFO) << "SW=" << sw_id << " port(portStats)=" << elemBT->second.PortNo << " :: drop=" << it.second.drop
                    //            << " :: drop0x4=" << it.second.drop_0x4
                    //            << " : packets=" << it.second.packets << " : flows=" << it.second.flows;
                    if (elemST != CSModPtr->stats_[sw_id].ports.end()) {
                        elemST->second.isCheck = true;
                        //LOG(INFO) << "SW=" << sw_id << " port(stats_)=" << elemST->first << " :: drop=" << elemST->second.drop
                        //            << " :: drop0x4=" << elemST->second.drop_0x4
                        //            << " : diff_drop=" << elemST->second.diff_drop;
                        
                        if (it.second.drop >= elemST->second.drop) 
                            diff = it.second.drop - elemST->second.drop;
                        else diff = 0;

                        if (it.second.drop_0x4 >= elemST->second.drop_0x4) 
                            diff_0x4 = it.second.drop_0x4 - elemST->second.drop_0x4;
                        else {
                            diff_0x4 = (it.second.drop_0x4 > 0) ? (elemST->second.drop_0x4 / it.second.drop_0x4)*2 : 0;
                        }

                        if ((diff < 2*common_t) && (diff) && (elemST->second.type != INF)) {
                            CFModPtr->delete_old_flows(sender_, it.first, elemBT->second.getStrIP(), 
                                                                        sw_id,  elemBT->second.PortNo);
                            delete_all_flows(it.first);
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
                        elemST->second.diff_drop_0x4 = diff_0x4;
                        elemST->second.drop_0x4 = it.second.drop_0x4;
                        elemST->second.PNF = ((it.second.flows > 0) && (it.second.packets > 0)) ? 
                                                float(it.second.packets) / it.second.flows : commonPNF;

                        if (packetDrops_.find(it.first) != packetDrops_.end()){
                            int size = packetDrops_[it.first].size();
                            if (size) packetDrops_[it.first][size-1] = diff + diff_0x4;
                        }
                        else {
                            std::vector<int> elem;
                            int size = (currentTestTime)  ? currentTestTime/tau : 1;
                            for (auto i = 0; i < size; i++) {
                                elem.push_back(0);
                            }
                            elem.push_back(diff+diff_0x4);
                            packetDrops_.emplace(it.first,std::move(elem));
                        }
                    }
                
                }
            }  

            for (auto itPort = CSModPtr->stats_[sw_id].ports.begin(); 
                        itPort != CSModPtr->stats_[sw_id].ports.end(); itPort++) {
                if (!itPort->second.isCheck) {
                    itPort->second.diff_drop = 0;
                    itPort->second.diff_drop_0x4 = 0;
                }
                itPort->second.isCheck=false;
            }

            if (clear_table && !CLEAR) numberClearSW++;  
            if ((numberClearSW == CSModPtr->stats_.size()) && !CLEAR) {
                CLEAR = true;
                LOG(INFO) << "!!!!!!!!!!!!!!!!!!END CLEAR TABLES!!!!!!!!!!!!!!!!!!!";
            }
        }
        return false;
    }, -30);

    //for testing without DDDF
    //-----------------------------------
    if (!appEnabled) {
        infectedIPs_.insert("10.0.0.1");
        infectedIPs_.insert("10.0.0.5");
        infectedIPs_.insert("10.255.255.254");
    }
    //-----------------------------------

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
    if (logEnabled) {
        LOG(INFO) << "**********************************************";
        LOG(INFO) << "CURRENT TIME " << current_time;
    }

    get_cpu_util();

    bool isCommonInterval = (current_time % (common_t)) ? false : true;
    if (computeFP_FN && startLogInfoForFPFN) {
        currentTestTime+=tau;
        LOG(INFO) << "LOG FOR FP FN time=" << currentTestTime;
        if (isCommonInterval) {
            for (auto& itMAC : packetIns_) itMAC.second.push_back(0);
            for (auto& itMAC : packetDrops_) itMAC.second.push_back(0);
        }
        else {
            for (auto& itMAC : packetIns_) itMAC.second.push_back(-1);
            for (auto& itMAC : packetDrops_) itMAC.second.push_back(-1);
        }
    }
    

    if (appEnabled) {
        if (sw_response_number >= CSModPtr->numberSW) {
            if (!ATTACK) {
                CSModPtr->comparison(); 
                if (!ATTACK) {
                    if (logEnabled) {
                        LOG(INFO) << "----------------------------------------";
                        CSModPtr->printStats();
                        LOG(INFO) << "----------------------------------------";
                    }
                    trackINFHosts(); 
                }
            }
            else {
                if (logEnabled) {
                    LOG(INFO) << "----------------------------------------";
                    CSModPtr->printStats();
                    LOG(INFO) << "----------------------------------------";
                }
            }
            
            sw_response_number = 0;
        }
    }

    if(isCommonInterval && !ATTACK) {
        CFModPtr->getFlowStats(sender_);
        CFModPtr->save_switches_to_database(db_connector_);
        CSModPtr->save_stats_to_database(db_connector_);
        save_BT_to_database();

        //for testing
        //-----------------------------------
        if (!appEnabled)
            if ((infectedIPs_.size() > infectedMACs_.size()) && (currentTestTime > 21)) 
                fillInfectedMACs();
        //-----------------------------------
    }
    if (ATTACK) {
        if (appEnabled)
            checkScore();
            
        if (ATTACK)
            CFModPtr->getFlowStats(sender_);
        else {
            if (isCommonInterval) {
                CFModPtr->getFlowStats(sender_);
            }
        }
        
    }

    if (computeFP_FN && (currentTestTime > testDuration) && !isPacketsAmountSaved) {
        savedInfoForComputeFPFN();
        isPacketsAmountSaved = true;
    }

    if (logEnabled)
        if (isCommonInterval) {
            CFModPtr->printSwitches();
            LOG(INFO) << "----------------------------------------";
            printBindingTable();
            LOG(INFO) << "**********************************************";
        }

    CSModPtr->clean();
}

void DDoS_Defender::savedInfoForComputeFPFN() {
    std::ofstream fout;
    fout.open("src/apps/ddos-defender/tests/infoForFPandFN.txt", std::ios_base::out | std::ios_base::trunc );
    if (!fout.is_open())
        LOG(INFO) << "Can't create file infoForFPandFN.txt!";
    LOG(INFO) << "INFO for compute FP and FN";
    fout << "{";
    uint nMAC = 0, sizeMACs = packetIns_.size();
    for (auto itMAC : packetIns_) {
        auto itBT = BindingTable_.find(itMAC.first);
        if (itBT != BindingTable_.end()) {
            fout << "'" << itBT->second.getStrIP() << "' : [";
            for (uint i = 0; i < itMAC.second.size(); i++) {
                LOG(INFO) << "mac=" << itMAC.first << " packetIn[" << i << "]=" << itMAC.second[i];
                fout << itMAC.second[i];
                if ((i+1) < itMAC.second.size()) fout << ",";
                else fout << "]";
            }
            if ((nMAC+1) < sizeMACs) fout << ",";
        }
        nMAC++;
    }
    fout << "}\n";
    nMAC = 0, sizeMACs = packetDrops_.size();
    fout << "{";
    for (auto itMAC : packetDrops_) {
        auto itBT = BindingTable_.find(itMAC.first);
        if (itBT != BindingTable_.end()) {
            fout << "'" << itBT->second.getStrIP() << "' : [";
            for (uint i = 0; i < itMAC.second.size(); i++) {
                LOG(INFO) << "mac=" << itMAC.first << " packetDrop[" << i << "]=" << itMAC.second[i];
                fout << itMAC.second[i];
                if ((i+1) < itMAC.second.size()) fout << ",";
                else fout << "]";
            }
            if ((nMAC+1) < sizeMACs) fout << ",";
        }
        nMAC++;
    }
    fout << "}\n";
    fout.close();
}

void DDoS_Defender::fillInfectedMACs() {
    for (auto itBT : BindingTable_) {
        if (infectedIPs_.find(itBT.second.getStrIP()) != infectedIPs_.end()) {
            infectedMACs_.insert(itBT.first);
        }
    }
}

void DDoS_Defender::checkScore(){
    float score = 0;
    bool is_attack_end = true;
    for (auto itSW = CSModPtr->stats_.begin(); itSW != CSModPtr->stats_.end(); itSW++) {
        for (auto itPort = itSW->second.ports.begin(); itPort != itSW->second.ports.end(); itPort++) {
            if ((itPort->second.type == AMB) && (itPort->second.PNF > 10)) 
                itPort->second.PNF = commonPNF;
            score = (itPort->second.gamma_per_tau) ? 
                        itPort->second.PNF / itPort->second.gamma_per_tau :
                        itPort->second.PNF;
            score = score*(1-alpha) + itPort->second.score*alpha;
            if (itPort->second.type != INF) {
                itPort->second.score = score;
                if (score <= threshold_low) {
                    itPort->second.type = INF; 
                    send_drop_flows(itSW->first,itPort->first);
                    std::string sw_port = boost::lexical_cast<std::string>(itSW->first) + 
                                            boost::lexical_cast<std::string>(itPort->first);
                    auto itMAC = CFModPtr->sw_port_to_MAC.find(sw_port);
                    if (itMAC != CFModPtr->sw_port_to_MAC.end()) {
                        infectedMACs_.insert(itMAC->second);
                        auto itBT = BindingTable_.find(itMAC->second);
                        if (itBT != BindingTable_.end()) {
                            LOG(INFO) << "host mac=" << itMAC->second << " : ip=" 
                                        << itBT->second.getStrIP() 
                                        << " : sw=" << itSW->first << " : port=" << itPort->first
                                        << " come INFECTED with score=" << itPort->second.score;
                        }
                    }
                    itSW->second.betaInf += itPort->second.gamma_per_tau;
                    itPort->second.drop_0x4 = itPort->second.gamma_per_tau;
                }
                else {
                    if ((score >= threshold_hight) && (itPort->second.type != USR)) {
                        itPort->second.type = USR;
                        std::string sw_port = boost::lexical_cast<std::string>(itSW->first) + 
                                                boost::lexical_cast<std::string>(itPort->first);
                        auto itMAC = CFModPtr->sw_port_to_MAC.find(sw_port);
                        auto itBT = BindingTable_.find(itMAC->second);
                        LOG(INFO) << "host mac=" << itMAC->second << " : ip=" 
                                        << itBT->second.getStrIP() 
                                        << " : sw=" << itSW->first << " : port=" << itPort->first
                                        << " come USERS with score=" << itPort->second.score;
                    }
                    else { 
                        if ((score < threshold_hight) && (cpu_util > threshold_cpu_util)) {
                            itPort->second.type = INF;
                            send_drop_flows(itSW->first,itPort->first);
                            std::string sw_port = boost::lexical_cast<std::string>(itSW->first) + 
                                                    boost::lexical_cast<std::string>(itPort->first);
                            auto itMAC = CFModPtr->sw_port_to_MAC.find(sw_port);
                            if (itMAC != CFModPtr->sw_port_to_MAC.end()) {
                                infectedMACs_.insert(itMAC->second);
                                auto itBT = BindingTable_.find(itMAC->second);
                                if (itBT != BindingTable_.end()) {
                                    LOG(INFO) << "host mac=" << itMAC->second << " : ip=" 
                                                << itBT->second.getStrIP() 
                                        << " : sw=" << itSW->first << " : port=" << itPort->first
                                                << " come INFECTED with score=" << itPort->second.score;
                                }
                            }
                            itSW->second.betaInf += itPort->second.gamma_per_tau;
                            itPort->second.drop_0x4 = itPort->second.gamma_per_tau;
                        }
                        else if ((itPort->second.type != AMB) && (score < threshold_hight)) {
                            itPort->second.type = AMB;
                            std::string sw_port = boost::lexical_cast<std::string>(itSW->first) + 
                                                    boost::lexical_cast<std::string>(itPort->first);
                            auto itMAC = CFModPtr->sw_port_to_MAC.find(sw_port);
                            if (itMAC != CFModPtr->sw_port_to_MAC.end()) {
                                auto itBT = BindingTable_.find(itMAC->second);
                                if (itBT != BindingTable_.end()) {
                                    LOG(INFO) << "host mac=" << itMAC->second << " : ip=" 
                                                << itBT->second.getStrIP()
                                        << " : sw=" << itSW->first << " : port=" << itPort->first
                                                << " come AMBIGUOUS with score=" << itPort->second.score;
                                }
                            }
                        }
                    }
                }
            }
            if (itPort->second.type == AMB) is_attack_end = false;
        }
    }
    if (is_attack_end && (CSModPtr->sumBeta <= omega)) {
        ATTACK = !is_attack_end;
        LOG(INFO) << "!!!!!!!!!!!!!!!!!!!!!ATTACK END!!!!!!!!!!!!!!!!!!!!!!!!!!";
        CSModPtr->sumBeta = 0;
        CSModPtr->sumLambda = 0;
        for (auto itSW=CSModPtr->stats_.begin(); itSW!=CSModPtr->stats_.end(); itSW++){
            itSW->second.beta = 0;
            itSW->second.lambda = 0;
        }
        numberClearSW = 0;
        CLEAR = false;
        cleanTables();
    }
}

void DDoS_Defender::cleanTables() {
    for (auto infMAC : infectedMACs_) {
        delete_all_flows(infMAC);
    }
}

void DDoS_Defender::delete_all_flows(std::string MAC) {
    for (auto itSW : CSModPtr->stats_) {
        //LOG(INFO) << "send delete flows to SW=" << itSW.first << " for MAC=" << infMAC;
        {
            of13::FlowMod fm1, fm2;
            std::stringstream ss;
            fm1.command(of13::OFPFC_DELETE); fm2.command(of13::OFPFC_DELETE);
            fm1.table_id(of13::OFPTT_ALL); fm2.table_id(of13::OFPTT_ALL);
            fm1.priority(2); fm2.priority(2);
            fm1.cookie(0x0); fm2.cookie(0x0);
            fm1.cookie_mask(0); fm2.cookie_mask(0);
            fm1.idle_timeout(uint64_t(60)); fm2.idle_timeout(uint64_t(60)); 
            fm1.hard_timeout(uint64_t(1800)); fm2.hard_timeout(uint64_t(1800)); 

            ethaddr eth_src(MAC);
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
        {
            of13::FlowMod fm1, fm2;
            std::stringstream ss;
            fm1.command(of13::OFPFC_DELETE); fm2.command(of13::OFPFC_DELETE);
            fm1.table_id(of13::OFPTT_ALL); fm2.table_id(of13::OFPTT_ALL);
            fm1.priority(2); fm2.priority(2);
            fm1.cookie(0x0); fm2.cookie(0x0);
            fm1.cookie_mask(0); fm2.cookie_mask(0);
            fm1.idle_timeout(uint64_t(60)); fm2.idle_timeout(uint64_t(60)); 
            fm1.hard_timeout(uint64_t(1800)); fm2.hard_timeout(uint64_t(1800)); 

            ethaddr eth_src(MAC);
            ss.str(std::string());
            ss.clear();
            ss << eth_src;
            fm1.add_oxm_field(new of13::EthDst{fluid_msg::EthAddress(ss.str())});
            fm2.add_oxm_field(new of13::EthDst{fluid_msg::EthAddress (ss.str())});

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
            if (itSW->second.betaInf < itSW->second.alpha) {
                for (auto itPort = itSW->second.ports.begin(); itPort!=itSW->second.ports.end(); itPort++) {
                    auto sw = CFModPtr->switches_.find(itSW->first);
                    if (sw != CFModPtr->switches_.end()) {
                        auto port = sw->second.ports.users.find(itPort->first);
                        if (port != sw->second.ports.users.end()) {
                            if ((itPort->second.type == INF) && (port->second)) {
                                std::string sw_port = boost::lexical_cast<std::string>(itSW->first) + 
                                                        boost::lexical_cast<std::string>(itPort->first);
                                auto itMAC = CFModPtr->sw_port_to_MAC.find(sw_port);
                                auto itBT = BindingTable_.find(itMAC->second);
                                itPort->second.type = USR;
                                itPort->second.score = threshold_hight;
                                auto it = infectedMACs_.find(itMAC->first);
                                if (it != infectedMACs_.end()) infectedMACs_.erase(it);
                                delete_drop_flows(itSW->first,itPort->first);
                                LOG(INFO) << "trackINFHosts => infected host mac=" << itMAC->second << " : ip=" << itBT->second.getStrIP() << " come USERS"; 
                                            //<< itPort->second.score
                                            //<< " : type=" << itPort->second.whatType();
                    }
                        }
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
                itSW->second.betaInf += itPort.second.diff_drop_0x4;
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
        if (isCommonInterval) sumBeta = 0;
        for (auto itSW=stats_.begin(); itSW!=stats_.end(); itSW++){
            if (isBigInterval) {
                
                itSW->second.beta = 0;
                itSW->second.betaInf = 0;
            }
            if (isBigInterval) {
                itSW->second.lambda = 0;
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
    //LOG(INFO) << "SEND DROP FLOWS to SW=" << sw_id << " : port=" << port;
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

void DDoS_Defender::delete_drop_flows(uint64_t sw_id, uint32_t port) {
    //LOG(INFO) << "DELETE DROP FLOWS to SW=" << sw_id << " : port=" << port;
    of13::FlowMod fm1, fm2;
    fm1.command(of13::OFPFC_DELETE); fm2.command(of13::OFPFC_DELETE);
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
        else {
            //for testing
            //-----------------------------------
            /*
            of13::MultipartRequestFlow mprf;
            mprf.table_id(of13::OFPTT_ALL);
            mprf.out_port(of13::OFPP_ANY);
            mprf.out_group(of13::OFPG_ANY);
            mprf.cookie(0x0);
            mprf.cookie_mask(0x0);
            mprf.flags(0);
            sender->send(it.first, mprf);
            */
            //-----------------------------------
        }
    }
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
            LOG(INFO) << itPort.first << " : gamma_per_tau=" << itPort.second.gamma_per_tau
                        << " : drop=" << itPort.second.drop
                        << " : diff_drop=" << itPort.second.diff_drop 
                        << " : drop_0x4=" << itPort.second.drop_0x4
                        << " : diff_drop_0x4=" << itPort.second.diff_drop_0x4 
                        << " : PNF=" << itPort.second.PNF
                        << " : score=" << itPort.second.score 
                        << " : type=" << itPort.second.whatType();
        }
        LOG(INFO) << "beta=" << itSW.second.beta << " : betaInf=" << itSW.second.betaInf << 
                    " : lambda=" << itSW.second.lambda << 
                     " : alpha=" << itSW.second.alpha;
    }
    LOG(INFO) << "numberSW=" << numberSW << " : sumBeta=" << sumBeta << " : sumLambda=" << sumLambda;
}

void DDoS_Defender::printInfectedMACs() {
    LOG(INFO) << "infected MACs (size = " << infectedMACs_.size() << ") :";
    for (auto it : infectedMACs_) {
        LOG(INFO) << "    " << it;
    }
}

void DDoS_Defender::printSwPortToMAC() {
    LOG(INFO) << "SW ports to MACs (size = " << CFModPtr->sw_port_to_MAC.size() << ") :";
    for (auto it : CFModPtr->sw_port_to_MAC) {
        LOG(INFO) << "    " << it.first << " : " << it.second;
    }
}
}