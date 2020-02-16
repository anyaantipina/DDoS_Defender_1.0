#pragma once

#include "Application.hpp"
#include "Controller.hpp"
#include "api/Switch.hpp"
#include "Loader.hpp"
#include "HostManager.hpp"

#include "oxm/openflow_basic.hh"
#include "oxm/field_set.hh"
#include <boost/lexical_cast.hpp>

#include <string>
#include <unordered_map>
#include <unordered_set>


namespace runos {

namespace of13 = fluid_msg::of13;

struct host_info {
    host_info(std::string, std::string, uint32_t, uint64_t);
    host_info();
    std::string mac;
    std::string ip;
    uint32_t switch_port;
    uint64_t switch_id;
};


struct ports {
    ports();
    std::set<uint32_t> trusted;
    std::set<uint32_t> user;
    std::set<uint32_t> ambiguous;
    std::set<uint32_t> infected;
};


struct score{
    score();
    host_info host;
    std::string type;
    float prev_counter;
    float curr_counter;
    float good_flows;
    float all_flows;
    float crit;
    float prev_score;
};


struct counters{
    counters();
    int curr_counter;
    int prev_counter;
};

class DDoS_Defender : public Application {
    Q_OBJECT
    SIMPLE_APPLICATION(DDoS_Defender, "ddos-defender")
private:
    OFMessageHandlerPtr handler_;
    bool ATTACK;
    bool BuildDone;
    bool HostsDone;
    static int THRESHOLD;
    static int crit_good_flows;
    static float alpha;
    static int interval;
    //bool test_interval; //for testing

    SwitchManager* switch_manager_;
    std::vector<host_info> hosts;
    std::unordered_map<std::string, host_info> RevIPBindTable;
    std::unordered_map<std::string, host_info> IPBindTable;
    std::unordered_map<uint64_t, ports> switches;
    std::unordered_map<std::string, score> src_criterion;
    std::unordered_map<std::string, counters> attack_end;
    std::unordered_map<uint64_t, bool> sw_response;

    //std::unordered_map<uint64_t,flow_stat> switch_flow_test; //for testing

    void add_to_RevTable(std::string, std::string, uint32_t, uint64_t);

    void check_RevTable();

    void build_IPBindTable();
    void build_ports_set();

    void get_cpu_util();
    void get_flow_stats();

    void timerEvent(QTimerEvent*) override;

    void send_init_flowmods();

    //for testing
    //void add_flow_statistic_from_switch(std::vector<of13::FlowStats>, uint64_t);
    //void print_flow_test();

    void add_src_statistic_from_switch(std::vector<of13::FlowStats>, uint64_t);
    void init_src_criterion();
    void check_src_criterion(uint64_t);
    //void check_attack_end();

    void print_ip_table();
    void print_rev_ip_table();
    void print_hosts();
    void print_ports();
    void print_flow_stats(std::vector<of13::FlowStats>);
    void print_src_criterion();
    //void print_attack_end();
public:
    void init(Loader* loader, const Config& config) override;
    void startUp(Loader*);
signals:
    void new_port(SwitchConnectionPtr ofconn, of13::PortStatus ps);
};

}