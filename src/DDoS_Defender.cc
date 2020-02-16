#include "DDoS_Defender.hpp"

#include "PacketParser.hpp"

#include <algorithm>
#include <unistd.h>
#include <sys/types.h>
#include "sys/times.h"
#include "sys/vtimes.h"
#include <fluid/util/ipaddr.hh>

//FOR TREE TOPOLOGY
int DDoS_Defender::crit_good_flows = 3;
float DDoS_Defender::alpha = 0.4;
float DDoS_Defender::threshold_low = 0.25;
float DDoS_Defender::threshold_hight = 0.4;
int DDoS_Defender::THRESHOLD = 20;
double DDoS_Defender::cpu_util = 0.0;
int DDoS_Defender::interval = 3;
double DDoS_Defender::threshold_cpu_util = 25;
unsigned int DDoS_Defender::hosts_amount = 8;

static clock_t lastCPU, lastSysCPU, lastUserCPU;

namespace runos {

REGISTER_APPLICATION(DDoS_Defender, {"controller", "host-manager", ""})

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

void DDoS_Defender::init(Loader *loader, const Config &rootConfig){

    auto config = config_cd(rootConfig, "ddos-defender");
    crit_good_flows = config_get(config, "crit_good_flows", 3);
    alpha = string_to_float(config_get(config, "alpha", "0.4").c_str());
    threshold_low = string_to_float(config_get(config, "threshold_low", "0.1").c_str());
    threshold_hight = string_to_float(config_get(config, "threshold_hight", "0.4").c_str());
    THRESHOLD = config_get(config, "THRESHOLD",20);
    interval = config_get(config, "interval", 3);
    hosts_amount = config_get(config, "hosts_amount", 8);

    //test_interval = false; //FOR TESTING
    init_cpu_util();

    BuildDone = false;
    HostsDone = false;
    ATTACK = false;
    Controller *ctrl = Controller::get(loader);
    HostManager *hm = HostManager::get(loader);
    sm = SwitchManager::get(loader);

    //ADD HOSTS
    QObject::connect(hm, &HostManager::hostDiscovered, [this](Host* dev){
        host_info host(dev->mac(), dev->ip(), dev->switchPort(), dev->switchID());
        hosts.push_back(host);
    });

    //RESPONSE TO FLOW STATS REPLY
    oftran = ctrl->registerStaticTransaction(this);
    QObject::connect(oftran, &OFTransaction::response,
          [this](SwitchConnectionPtr conn, std::shared_ptr<OFMsgUnion> reply){
        uint64_t sw_id = conn->dpid();
        OFMsg* basereply = reply->base();
        of13::MultipartReply* mpreply = (of13::MultipartReply*)basereply;
        std::vector<of13::FlowStats> flow_stats =
                ((of13::MultipartReplyFlow*)mpreply)->flow_stats();

        //FOR TESTING
        /*if (!test_interval) {
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
            print_flow_test();
            test_interval = false;
        }*/

        add_src_statistic_from_switch(flow_stats, sw_id);

        bool is_filled = true;
        sw_response[sw_id] = true;
        for (auto it : sw_response)
            if (it.second == false) {
                is_filled = false;
            }

        /*if (ATTACK) {
            check_src_criterion(sw_id);
            if (is_filled == true) {
                check_attack_end();
            }
            //print_attack_end();
        }*/
    });

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

        if (!BuildDone) { // BUILDING IP_BIND_TABLE
                add_to_RevTable(str_mac, str_ip, in_port, dpid);
                check_RevTable();
        }
        /*else { // INCREASING SRC PACKET_IN COUNTER
            std::string key = "MAC " + str_mac + " IP " + str_ip;
            if (src_criterion.find(key) != src_criterion.end()){
                src_criterion[key].curr_counter += 1;
                attack_end[key].curr_counter += 1;
                if ((src_criterion[key].curr_counter > THRESHOLD)
                        and (ATTACK == false)) {
                    LOG(INFO) << "TOO MANY PACKET_IN FROM " << key;
                    LOG(INFO) << "!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!";
                    ATTACK = true;
                }
            }
        }*/

        return false;
    }, -11);
}

void DDoS_Defender::startUp(Loader* ) {
    LOG(INFO) << "DDoS_Defender::startUp";
    startTimer(interval*1000);
}


void DDoS_Defender::timerEvent(QTimerEvent*) {
    if (BuildDone){
        get_cpu_util();
        get_flow_stats();
    }
    else if (HostsDone) {
        build_IPBindTable();
        print_ip_table();
        build_ports_set();
        print_ports();
        init_src_criterion();
        send_init_flowmods();
        BuildDone = true;
    }
    else {
        //print_hosts();
        //print_rev_ip_table();
    }
}

}

void DDoS_Defender::add_to_RevTable(std::string mac, std::string ip, uint32_t port_no, uint64_t sw_id){
    std::string key = "MAC " + mac + " IP " + ip;
    auto find_key = RevIPBindTable.find(key);
    if (find_key == RevIPBindTable.end()){
        host_info host(mac, ip, port_no, sw_id);
        RevIPBindTable.insert({key,host});
        int index = 0;
        for (auto it_hosts : hosts){
            if ((it_hosts.mac == mac) and (it_hosts.ip == "0.0.0.0")) {
                hosts[index] = host;
                break;
            }
            index++;
        }
    }
    else {
        host_info host(mac, ip, find_key->second.switch_port, find_key->second.switch_id);
        RevIPBindTable[key] = host;
        int index = 0;
        for (auto it_hosts : hosts){
            if ((it_hosts.mac == mac) and (it_hosts.ip == "0.0.0.0")) {
                hosts[index] = host;
                break;
            }
            index++;
        }
    }

    //print_rev_ip_table();
}

void DDoS_Defender::check_RevTable(){
    //print_hosts();
    bool find_all_hosts = true;
    unsigned int not_zero_ip = 0;
    if (hosts.size() == 0) {
        find_all_hosts = false;
    }
    for (auto it_hosts : hosts) {
        bool find_host = false;
        for (auto it_revtable : RevIPBindTable) {
            if (it_hosts.mac == it_revtable.second.mac) {
                find_host = true;
                if (it_revtable.second.ip != "0.0.0.0"){
                    not_zero_ip++;
                    break;
                }
            }
        }
        if (!find_host) {
            find_all_hosts = false;
            break;
        }
    }
    if (find_all_hosts and (not_zero_ip==hosts_amount)) {
        HostsDone = true;
    }
}

void DDoS_Defender::build_IPBindTable(){
    for (auto it_hosts : hosts) {
        for (auto it_rev_table : RevIPBindTable){
            if (((it_hosts.ip == it_rev_table.second.ip) or (convert_ip_addr(it_hosts.ip) == it_rev_table.second.ip))
                and (it_hosts.mac == it_rev_table.second.mac) and (it_hosts.ip != "0.0.0.0")){
                host_info host(it_rev_table.second.mac, it_rev_table.second.ip,
                               it_rev_table.second.switch_port, it_rev_table.second.switch_id);
                std::string key = "MAC " + it_rev_table.second.mac + " IP " + it_rev_table.second.ip;
                IPBindTable.insert({key, host});
                break;
            }
        }
    }
    RevIPBindTable.clear();
}

void DDoS_Defender::build_ports_set(){
    std::set<uint64_t> switches_set;
    for (auto it_ip_table : IPBindTable){
        auto find_switch = switches_set.find(it_ip_table.second.switch_id);
        if (find_switch != switches_set.end()) {
            switches[*find_switch].user.insert(it_ip_table.second.switch_port);
        }
        else {
            ports elem;
            elem.user.insert(it_ip_table.second.switch_port);
            switches.insert({it_ip_table.second.switch_id, elem});
            sw_response.insert({it_ip_table.second.switch_id, false});
            //flow_stat elem2; //for testing
            //switch_flow_test.insert({it_ip_table.second.switch_id, elem2}); //for testing
            switches_set.insert(it_ip_table.second.switch_id);
        }
    }
    for (auto it_switch_set : switches){
        Switch* sw = sm->getSwitch(it_switch_set.first);
        std::vector<of13::Port> ports = sw->ports();
        for (auto it_ports : ports){
            if (switches[it_switch_set.first].user.find(it_ports.port_no()) ==
                    switches[it_switch_set.first].user.end()) {
                switches[it_switch_set.first].trusted.insert(it_ports.port_no());
            }
        }
    }
    switches_set.clear();
}

void DDoS_Defender::init_src_criterion(){
    for (auto it : IPBindTable){
        score elem_score;
        elem_score.host = it.second;
        src_criterion.insert({it.first,elem_score});
        counters elem;
        attack_end.insert({it.first,elem});
    }
}

void DDoS_Defender::add_src_statistic_from_switch(std::vector<of13::FlowStats> flow_stats, uint64_t sw_id){
    //CLEAN OLD STATISTIC
    for (auto it_src_crit : src_criterion){
        if (src_criterion[it_src_crit.first].host.switch_id == sw_id) {
            src_criterion[it_src_crit.first].all_flows = 1;
            src_criterion[it_src_crit.first].good_flows = 1;
            src_criterion[it_src_crit.first].prev_counter = src_criterion[it_src_crit.first].curr_counter;
            src_criterion[it_src_crit.first].curr_counter = 1;
            attack_end[it_src_crit.first].prev_counter=src_criterion[it_src_crit.first].prev_counter;
            attack_end[it_src_crit.first].curr_counter=src_criterion[it_src_crit.first].curr_counter;
        }
    }
    //ADD NEW STATISTIC
    for (auto it : flow_stats){
        of13::FlowStats *flow1 = static_cast<of13::FlowStats *>(&it);
        of13::Match match = flow1->match();
        std::string mac, ip;
        if (match.eth_src())
            mac = match.eth_src()->value().to_string();
        if (match.ipv4_src()) {
            ip = AppObject::uint32_t_ip_to_string(match.ipv4_src()->value().getIPv4());
        }
        std::string key = "MAC " + mac + " IP " + ip;
        if (src_criterion.find(key) != src_criterion.end()){
            src_criterion[key].all_flows += 1;
            if (it.packet_count() > unsigned(crit_good_flows)){
                src_criterion[key].good_flows += 1;
            }
        }
    }
}

void DDoS_Defender::send_init_flowmods(){
    const auto ofb_in_port = oxm::in_port();
    const auto ofb_eth_type = oxm::eth_type();
    const auto ofb_ipv4_src = oxm::ipv4_src();
    const auto ofb_eth_src = oxm::eth_src();

    for (auto it_switch : switches){
        Switch* switch_ = sm->getSwitch(it_switch.first);

        //DROP ACTIONS
        for (auto host_port : it_switch.second.user){
            uint16_t priority = 0;
            priority += host_port;
            oxm::field_set m_match1, m_match2;
            m_match1.modify(ofb_in_port == host_port);
            m_match1.modify(ofb_eth_type == 0x0800);
            m_match2.modify(ofb_in_port == host_port);
            m_match2.modify(ofb_eth_type == 0x0806);

            of13::FlowMod fm1, fm2;
            fm1.command(of13::OFPFC_ADD); fm2.command(of13::OFPFC_ADD);
            fm1.xid(0); fm2.xid(0);
            fm1.buffer_id(OFP_NO_BUFFER); fm2.buffer_id(OFP_NO_BUFFER);
            fm1.table_id(0); fm2.table_id(0);
            fm1.priority(priority); fm2.priority(priority);
            fm1.cookie(0x0); fm2.cookie(0x0);
            fm1.idle_timeout(0); fm2.idle_timeout(0);
            fm1.hard_timeout(0); fm2.hard_timeout(0);
            fm1.flags( of13::OFPFF_CHECK_OVERLAP | of13::OFPFF_SEND_FLOW_REM );
            fm2.flags( of13::OFPFF_CHECK_OVERLAP | of13::OFPFF_SEND_FLOW_REM );
            fm1.match(make_of_match(m_match1)); fm2.match(make_of_match(m_match2));
            switch_->connection()->send(fm1);
            switch_->connection()->send(fm2);
        }

        //GOTOTABLE ACTIONS FOR TRUSTED PORTS
        for (auto trust_port : it_switch.second.trusted){
            oxm::field_set m_match;
            m_match.modify(ofb_in_port == trust_port);

            of13::FlowMod fm;
            fm.command(of13::OFPFC_ADD);;
            fm.xid(0);
            fm.buffer_id(OFP_NO_BUFFER);
            fm.table_id(0);
            fm.priority(1);
            fm.cookie(0x0);
            fm.idle_timeout(0);
            fm.hard_timeout(0);
            fm.flags( of13::OFPFF_CHECK_OVERLAP | of13::OFPFF_SEND_FLOW_REM );
            fm.match(make_of_match(m_match));
            of13::GoToTable go_to_table(1);
            fm.add_instruction(go_to_table);
            switch_->connection()->send(fm);
        }
    }

    //GOTOTABLE ACTIONS
    for (auto it_BindTable : IPBindTable) {
        Switch* switch_ = sm->getSwitch(it_BindTable.second.switch_id);
        ethaddr eth_src(it_BindTable.second.mac);
        //IPv4Addr ipv4_src(it_BindTable.second.ip);
        uint16_t priority = 20;
        priority += it_BindTable.second.switch_port;

        oxm::field_set m_match1, m_match2;
        m_match1.modify(ofb_in_port == it_BindTable.second.switch_port);
        m_match1.modify(ofb_eth_type == 0x0800);
        m_match1.modify(ofb_eth_src == eth_src);
        m_match1.modify(ofb_ipv4_src == it_BindTable.second.ip);
        m_match2.modify(ofb_in_port == it_BindTable.second.switch_port);
        m_match2.modify(ofb_eth_type == 0x0806);
        m_match2.modify(ofb_eth_src == eth_src);

        of13::FlowMod fm1, fm2;
        fm1.command(of13::OFPFC_ADD); fm2.command(of13::OFPFC_ADD);
        fm1.xid(0); fm2.xid(0);
        fm1.buffer_id(OFP_NO_BUFFER); fm2.buffer_id(OFP_NO_BUFFER);
        fm1.table_id(0); fm2.table_id(0);
        fm1.priority(priority); fm2.priority(priority);
        fm1.cookie(0x0); fm2.cookie(0x0);
        fm1.idle_timeout(0); fm2.idle_timeout(0);
        fm1.hard_timeout(0); fm2.hard_timeout(0);
        fm1.flags( of13::OFPFF_CHECK_OVERLAP | of13::OFPFF_SEND_FLOW_REM );
        fm2.flags( of13::OFPFF_CHECK_OVERLAP | of13::OFPFF_SEND_FLOW_REM );
        fm1.match(make_of_match(m_match1)); fm2.match(make_of_match(m_match2));
        of13::GoToTable go_to_table(1);
        fm1.add_instruction(go_to_table);
        fm2.add_instruction(go_to_table);
        switch_->connection()->send(fm1);
        switch_->connection()->send(fm2);
    }
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
    double percent;

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

void DDoS_Defender::get_flow_stats(){
    for (auto it : switches){
        Switch* sw = sm->getSwitch(it.first);
        of13::MultipartRequestFlow mprf;
        mprf.table_id(of13::OFPTT_ALL);
        mprf.out_port(of13::OFPP_ANY);
        mprf.out_group(of13::OFPG_ANY);
        mprf.cookie(0x0);
        mprf.cookie_mask(0x0);
        mprf.flags(0);
        oftran->request(sw->connection(),  mprf);
    }
    bool is_filled = true;
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
    }
}

//PRINTING FUNCTIONS

void DDoS_Defender::print_hosts(){
    LOG(INFO) << "hosts (size = " << hosts.size() <<") :";
    for (auto it : hosts){
        LOG(INFO) << "IP: " << it.ip << " MAC: " << it.mac << " sw: " << it.switch_id << " port " << it.switch_port;
    }
}

void DDoS_Defender::print_rev_ip_table(){
    LOG(INFO) << "RevIPBindTable (size = " << RevIPBindTable.size() <<") :";
    for (auto it : RevIPBindTable){
        LOG(INFO) << "IP: " << it.second.ip << " MAC: " << it.second.mac
                  << " sw: " << it.second.switch_id << " port: " << it.second.switch_port;
    }
}

void DDoS_Defender::print_ip_table(){
    LOG(INFO) << "IPBindTable (size = " << IPBindTable.size() <<") :";
    for (auto it : IPBindTable){
        LOG(INFO) << it.first << ", sw_id: " << it.second.switch_id
                  << ", port_no " << it.second.switch_port;
    }
}

void DDoS_Defender::print_ports(){
    LOG(INFO) << "Switches and port's set (size = " << switches.size() <<") :";
    for (auto it_sw_id : switches){
        std::string trust = "";
        for (auto it_t_p : it_sw_id.second.trusted){
            trust += std::to_string(it_t_p) + " ";
        }
        std::string user = "";
        for (auto it_h_p : it_sw_id.second.user){
            user += std::to_string(it_h_p) + " ";
        }
        std::string ambig = "";
        for (auto it_a_p : it_sw_id.second.ambiguous){
            ambig += std::to_string(it_a_p) + " ";
        }
        std::string infect = "";
        for (auto it_i_p : it_sw_id.second.infected){
            infect += std::to_string(it_i_p) + " ";
        }

        LOG(INFO) << "switch id " << it_sw_id.first << ", trusted ports: " << trust
                  << ", user ports: " << user
                  << ", ambiguous ports: " << ambig
                  << ", infected ports: " << infect;
    }
}

void DDoS_Defender::print_flow_stats(std::vector<of13::FlowStats> flow_stats){
    int index = 0;
    for (auto it : flow_stats){
        of13::FlowStats *flow1 = static_cast<of13::FlowStats *>(&it);
        of13::Match match = flow1->match();
        std::string mac, ip;
        if (match.eth_src())
            mac = match.eth_src()->value().to_string();
        else continue;
        if (match.ipv4_src()) {
            ip = AppObject::uint32_t_ip_to_string(match.ipv4_src()->value().getIPv4());
        }
        LOG(INFO) << "flow " << index << " MAC " << mac << " IP " << ip
                  << ", table id: " << unsigned(it.table_id())
                  << "idle_to: " << it.idle_timeout()
                  << ", hard_to: " << it.hard_timeout()
                  << ", packet count: " << it.packet_count();
        index++;
    }
}

void DDoS_Defender::print_src_criterion(){
    LOG(INFO) << "Src_criterion (size = " << src_criterion.size() <<") :";
    for (auto it : src_criterion){
        LOG(INFO) << it.first << " type " << it.second.type
                  << " packet_in_counter (prev = " << it.second.prev_counter
                  << ", curr = " << it.second.curr_counter << "), "
                  << " crit " << it.second.crit
                  << " score " << it.second.prev_score;
    }
}

//HOST-INFO STRUCTURE
host_info::host_info(std::string mac, std::string ip, uint32_t switch_port, uint64_t switch_id){
    this->ip = ip;
    this->mac = mac;
    this->switch_port = switch_port;
    this->switch_id = switch_id;
}
host_info::host_info(){
    this->ip = "";
    this->mac = "";
    this->switch_port = 0;
    this->switch_id = 0;
}

//PORT CLASSIFICATION STRUCTURE
ports::ports() {
    this->trusted = {};
    this->user = {};
    this->ambiguous = {};
    this->infected = {};
}

//HOST'S SCORE STRUCTURE
score::score(){
    this->type = "USER";
    this->prev_counter = 1;
    this->curr_counter = 1;
    this->good_flows = 1;
    this->all_flows = 1;
    this->crit = DDoS_Defender::threshold_hight;
    this->prev_score = DDoS_Defender::threshold_hight;
}

counters::counters(){
    this->curr_counter = 0;
    this->prev_counter = 0;
}

