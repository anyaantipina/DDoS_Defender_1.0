#pragma once

#include "Application.hpp"
#include "Controller.hpp"
#include "api/Switch.hpp"
#include "Loader.hpp"
#include "HostManager.hpp"
#include "DhcpServer.hpp"
#include "LinkDiscovery.hpp"
#include "SwitchManager.hpp"
#include "OFMsgSender.hpp"
#include "DatabaseConnector.hpp"
#include <json.hpp>

#include "oxm/openflow_basic.hh"
#include "oxm/field_set.hh"
#include <boost/lexical_cast.hpp>

#include <string>
#include <unordered_map>
#include <unordered_set>
#include <memory>


namespace runos {

namespace of13 = fluid_msg::of13;

enum Types {USR, AMB, INF};

class controlFilterModule {
public:
    struct SWobj {
        struct Ports {
            std::unordered_map<uint32_t,bool> users;
            std::unordered_map<uint32_t,bool> trusted;
            std::unordered_map<uint32_t,bool> unknown;
        } ports;
        bool Status;
        bool isEdge;

        bool isAllPortsOff();
        nlohmann::json to_json();

        SWobj(bool, bool);
    };

    std::unordered_map<uint64_t,SWobj> switches_;
    void save_switches_to_database(DatabaseConnector* dbc_);
    void load_switches_from_database(DatabaseConnector* dbc_);
    std::unordered_map<std::string,std::string> sw_port_to_MAC;

    void add_filtered_flows(OFMsgSender*, std::string, std::string, uint64_t, uint32_t);
    void delete_old_flows(OFMsgSender*, std::string, std::string, uint64_t, uint32_t);
    void getFlowStats(OFMsgSender*);
    int getNumUpSwitches();
    void printSwitches();
};

class collectStatsModule {
public:
    struct statsPort {
        int gamma_per_tau;
        int drop, diff_drop, drop_0x4, diff_drop_0x4;
        float PNF, score;
        bool isCheck;
        Types type;
        statsPort(int,int,int,int,int,float,float,bool,std::string);
        std::string whatType();
    };
    struct statsSW {
        std::unordered_map<uint32_t, statsPort> ports;
        int beta, betaInf, alpha, lambda;
        statsSW();
    };

    bool isAlphaExceed;
    int numberSW;
    int sumBeta, sumLambda;

    std::unordered_map<uint64_t,statsSW> stats_;
    void save_stats_to_database(DatabaseConnector* dbc_);
    void load_stats_from_database(DatabaseConnector* dbc_);

    collectStatsModule();
    void comparison();
    void clean();
    void recount();
    void printStats();
};



class DDoS_Defender : public Application {
    Q_OBJECT
    SIMPLE_APPLICATION(DDoS_Defender, "ddos-defender")

public:
    DDoS_Defender();
    void init(Loader* loader, const Config& config) override;
    void startUp(Loader*);
    
    struct BTinfo {
        ethaddr MAC;
        ipv4addr IP;
        ipv4addr oldIP;
        uint64_t DPID;
        uint32_t PortNo;
        bool Status;
        bool isHost;
        nlohmann::json to_json();
        BTinfo(ethaddr, ipv4addr, ipv4addr, uint64_t, uint32_t, bool, bool);

        std::string getStrMAC();
        std::string getStrIP();
    };

protected slots:
    void onHostDiscovered(Host* dev);
    void onAddrChanged(Client* dev);
    void onSwitchUp(SwitchPtr dev);
    void onSwitchDown(SwitchPtr dev);
    void onLinkUp(PortPtr dev);
    void onLinkDown(PortPtr dev);
    void onLinkDiscovered(switch_and_port from, switch_and_port to);
    void onRecovery();
    void onPrimary();

private:
    SwitchManager* switch_manager_;
    OFMsgSender* sender_;
    DatabaseConnector* db_connector_;
    OFMessageHandlerPtr handler_, handler_flow_stats_, handler_flow_removed_, handler_flow_mod_;

    void get_cpu_util();
    void timerEvent(QTimerEvent*) override;

    std::unique_ptr<controlFilterModule> CFModPtr;
    std::unique_ptr<collectStatsModule> CSModPtr;
    std::unordered_map<std::string,BTinfo> BindingTable_;
    std::unordered_set<std::string> infectedMACs_;
    void save_BT_to_database();
    void load_BT_from_database();
    void clear_database();
    void checkScore();
    void send_drop_flows(uint64_t,uint32_t);
    void delete_all_flows(std::string);
    void delete_drop_flows(uint64_t, uint32_t);
    void cleanTables();
    void trackINFHosts();
    void printBindingTable();
    void printInfectedMACs();
    void printSwPortToMAC();
    //for testing
    //-----------------------------------
    void checkTableUsage(std::unordered_map<std::string,int>);
    std::unordered_set<std::string> infectedIPs_;
    void fillInfectedMACs();
    std::unordered_map<std::string,std::vector<int>> packetIns_;
    std::unordered_map<std::string,std::vector<int>> packetDrops_;
    void savedInfoForComputeFPFN();
};

}