/* -*- P4_16 -*- */

#include <core.p4>
#include <tna.p4>

/*************************************************************************
 ************* C O N S T A N T S    A N D   T Y P E S  *******************
**************************************************************************/
typedef bit<48> mac_addr_t;
typedef bit<16> ether_type_t;
typedef bit<32> ipv4_addr_t;
typedef bit<8>  ip_proto_t;
typedef bit<16> l4_port_t;

const ether_type_t ETHERTYPE_IPV4 = 16w0x0800;
const ether_type_t ETHERTYPE_ARP = 16w0x0806;

const ip_proto_t IP_PROTO_ICMP = 1;
const ip_proto_t IP_PROTO_TCP = 6;
const ip_proto_t IP_PROTO_UDP = 17;

/*************************************************************************
 ********* N E T C A C H E    S P E C I F I C   T Y P E S  ***************
**************************************************************************/
typedef bit<8>  netcache_op_t;
typedef bit<48> netcache_key_t;
typedef bit<32> netcache_value_t;

const ether_type_t ETHERTYPE_NETCACHE = 0x3950;

const netcache_op_t NETCACHE_READ_REQUEST = 0x01;
const netcache_op_t NETCACHE_WRITE_REQUEST= 0x02;
const netcache_op_t NETCACHE_READ_REPLY   = 0x03;
const netcache_op_t NETCACHE_WRITE_REPLY  = 0x04;
const netcache_op_t NETCACHE_CACHE_HIT    = 0x05;

/*************************************************************************
 ***********************  H E A D E R S  *********************************
 *************************************************************************/

/*  Define all the headers the program will recognize             */
/*  The actual sets of headers processed by each gress can differ */

/* Standard ethernet header */
header ethernet_h {
    mac_addr_t   dst_addr;
    mac_addr_t   src_addr;
    ether_type_t   ether_type;
}

header ipv4_h {
    bit<4>   version;
    bit<4>   ihl;
    bit<8>   diffserv;
    bit<16>  total_len;
    bit<16>  identification;
    bit<3>   flags;
    bit<13>  frag_offset;
    bit<8>   ttl;
    ip_proto_t   protocol;
    bit<16>  hdr_checksum;
    ipv4_addr_t  src_addr;
    ipv4_addr_t  dst_addr;
}

header tcp_h {
    l4_port_t src_port;
    l4_port_t dst_port;
    bit<32> seq_no;
    bit<32> ack_no;
    bit<4> data_offset;
    bit<4> res;
    bit<8> flag;
    bit<16> window;
    bit<16> checksum;
    bit<16> urgent_ptr;
}

header udp_h {
    l4_port_t src_port;
    l4_port_t dst_port;
    bit<16> hdr_length;
    bit<16> checksum;
}

header netcache_h {
    netcache_op_t       op;
    netcache_key_t      key;
    netcache_value_t    value;
}

header ing_port_mirror_h {
    @padding bit<6> pad0;
    bit<10> mirror_session;
}

/*************************************************************************
 **************  I N G R E S S   P R O C E S S I N G   *******************
 *************************************************************************/
 
    /***********************  H E A D E R S  ************************/

struct my_ingress_headers_t {
    ethernet_h   ethernet;
    ipv4_h  ipv4;
    tcp_h   tcp;
    udp_h   udp;
    netcache_h  nc;
}

struct netcache_md_t {
    bit<16> index;
    bit<1>  exist;
    bit<1>  is_valid;
    mac_addr_t  ethernet_addr;
    ipv4_addr_t ipv4_addr;
    l4_port_t   udp_port;
}

    /******  G L O B A L   I N G R E S S   M E T A D A T A  *********/

struct my_ingress_metadata_t {
    netcache_md_t nc_md;
    bit<10>     mirror_session;
}

    /***********************  P A R S E R  **************************/
parser IngressParser(packet_in        pkt,
    /* User */    
    out my_ingress_headers_t          hdr,
    out my_ingress_metadata_t         meta,
    /* Intrinsic */
    out ingress_intrinsic_metadata_t  ig_intr_md)
{
    /* This is a mandatory state, required by Tofino Architecture */
    state start {
        // init metadata
        meta.nc_md = {0, 0, 0, 0, 0, 0};
        meta.mirror_session = 0;

        pkt.extract(ig_intr_md);
        pkt.advance(PORT_METADATA_SIZE);
        transition parse_ethernet;
    }

    state parse_ethernet {
        pkt.extract(hdr.ethernet);
        transition select(hdr.ethernet.ether_type) {
            ETHERTYPE_IPV4 : parse_ipv4;
        }
    }

    state parse_ipv4 {
        pkt.extract(hdr.ipv4);
        transition select(hdr.ipv4.protocol) {
            IP_PROTO_TCP    : parse_tcp;
            IP_PROTO_UDP    : parse_udp;
            default : accept;
        }
    }

    state parse_tcp {
        pkt.extract(hdr.tcp);
        transition accept;
    }

    state parse_udp {
        pkt.extract(hdr.udp);
        transition select(hdr.ethernet.ether_type) {
            ETHERTYPE_NETCACHE : parse_netcache;
            default : accept;  
        }
    }

    state parse_netcache {
        pkt.extract(hdr.nc);
        transition accept;
    }
}


    /***************** M O D U L E S  *********************/

#include "include/cms.p4"
#include "include/bf.p4"

    /***************** M A T C H - A C T I O N  *********************/

control Ingress(
    /* User */
    inout my_ingress_headers_t                       hdr,
    inout my_ingress_metadata_t                      meta,
    /* Intrinsic */
    in    ingress_intrinsic_metadata_t               ig_intr_md,
    in    ingress_intrinsic_metadata_from_parser_t   ig_prsr_md,
    inout ingress_intrinsic_metadata_for_deparser_t  ig_dprsr_md,
    inout ingress_intrinsic_metadata_for_tm_t        ig_tm_md)
{   
    CMS() cms;
    BF() bf;

    Random<bit<4>>() rng;

    action drop() {
        ig_dprsr_md.drop_ctl = 0x0;    // drop packet
        exit;
    }

    action nc_cache_check_act(bit<16> index) {
        meta.nc_md.index = index;
        meta.nc_md.exist = 1;
    }

    table nc_cache_check {
        key = {
            hdr.nc.key: exact;
        }
        actions = {
            nc_cache_check_act;
        }
        size = 65536;
    }

    action nc_copy_header_act() {
        meta.nc_md.ethernet_addr = hdr.ethernet.src_addr;
        meta.nc_md.ipv4_addr = hdr.ipv4.src_addr;
        meta.nc_md.udp_port = hdr.udp.src_port;
    }

    Register<bit<1>,_>(65536) nc_valid_reg;
    RegisterAction<bit<1>, _, bit<1>> (nc_valid_reg) nc_valid_reg_read = {
        void apply(inout bit<1> val, out bit<1> rv) {
            rv = val;
        }
    };
    RegisterAction<bit<1>, _, bit<1>> (nc_valid_reg) nc_valid_reg_clear = {
        void apply(inout bit<1> val, out bit<1> rv) {
            val = 0;
            rv = 0;
        }
    };
    RegisterAction<bit<1>, _, bit<1>> (nc_valid_reg) nc_valid_reg_set = {
        void apply(inout bit<1> val, out bit<1> rv) {
            val = 1;
            rv = 1;
        }
    };

    action nc_valid_check_act () {
        meta.nc_md.is_valid = nc_valid_reg_read.execute(meta.nc_md.index);
    }

    action nc_valid_clear_act () {
        meta.nc_md.is_valid = nc_valid_reg_clear.execute(meta.nc_md.index);
    }

    action nc_valid_set_act () {
        meta.nc_md.is_valid = nc_valid_reg_set.execute(meta.nc_md.index);
    }

    Register<bit<32>,_>(65536) nc_value_reg;
    RegisterAction<bit<32>, _, bit<32>> (nc_value_reg) nc_value_reg_read = {
        void apply(inout bit<32> val, out bit<32> rv) {
            rv = val;
        }
    };
    RegisterAction<bit<32>, _, bit<32>> (nc_value_reg) nc_value_reg_update = {
        void apply(inout bit<32> val, out bit<32> rv) {
            val = hdr.nc.value;
            rv = val;
        }
    };

    action nc_value_read_act () {
        hdr.nc.value = nc_value_reg_read.execute(meta.nc_md.index);

        // Exchange src with dst 
        hdr.ethernet.src_addr = hdr.ethernet.dst_addr;
        hdr.ethernet.dst_addr = meta.nc_md.ethernet_addr;
        hdr.ipv4.src_addr = hdr.ipv4.dst_addr;
        hdr.ipv4.dst_addr = meta.nc_md.ipv4_addr;
        hdr.udp.src_port = hdr.udp.dst_port;
        hdr.udp.dst_port = meta.nc_md.udp_port;

        // Set op
        hdr.nc.op = NETCACHE_CACHE_HIT;
    }

    action nc_value_update_act () {
        nc_value_reg_update.execute(meta.nc_md.index);
    }

    Register<bit<32>,_>(65536) nc_hit_counter;
    RegisterAction<bit<32>, _, bit<32>> (nc_hit_counter) nc_hit_counter_update = {
        void apply(inout bit<32> val, out bit<32> rv) {
            val = val |+| 1;
        }
    };

    action nc_hit_counter_update_act() {
        nc_hit_counter_update.execute(meta.nc_md.index);
    }

    bit<32> miss_count = 0;
    bit<1>  to_report = 0;
    bit<1>  send_to_controller = 0;

    action nc_miss_threshold_hit_act() {
        to_report = 1;
    }

    table threshold {
        key = {
            // TODO: this needs to be slightly readjusted
            miss_count[19:0] : range;
        }
        actions = {
            nc_miss_threshold_hit_act;
            NoAction;
        }
        default_action = NoAction();
        size = 1;
    }

    action mirror_packet_to_controller_act(bit<10> mirror_session) {
        meta.mirror_session = mirror_session;
        ig_dprsr_md.mirror_type = 1;
    }

    table hh_report {
        key = {
            send_to_controller : exact;
        }
        actions = {
            mirror_packet_to_controller_act;
            NoAction;
        }
        default_action = NoAction;
    }

    action forward(PortId_t port) {
        ig_tm_md.ucast_egress_port = port;
    }

    table ipv4_forward {
        key = {
            ig_intr_md.ingress_port : exact;
        }
        actions = {
            forward;
            NoAction;
        }
        default_action = NoAction();
    }
        
    apply {
        if(hdr.nc.isValid()) {
            nc_cache_check.apply();
        
            if(meta.nc_md.exist == 1) {
                // cache hit
                if(hdr.nc.op == NETCACHE_READ_REQUEST) {
                    nc_valid_check_act();
                } else if(hdr.nc.op == NETCACHE_WRITE_REQUEST) {
                    nc_valid_clear_act();
                } else if (hdr.nc.op == NETCACHE_WRITE_REPLY || hdr.nc.op == NETCACHE_READ_REPLY) {
                    nc_valid_set_act();
                }

                // if valid, get value
                if (meta.nc_md.is_valid == 1) {
                    nc_copy_header_act();

                    if (hdr.nc.op == NETCACHE_READ_REQUEST) {
                        nc_value_read_act();
                        nc_hit_counter_update_act();
                    } else if (hdr.nc.op == NETCACHE_WRITE_REPLY || hdr.nc.op == NETCACHE_READ_REPLY) {
                        nc_value_update_act();
                    }
                }
            } else {
                // cache miss
                bit<4> random_number = rng.get();
                if(random_number == 0) {    // 1/16 sampling chance
                    cms.apply(hdr, miss_count);
                    threshold.apply();
                    if(to_report == 1) {
                        bf.apply(hdr, send_to_controller);
                        hh_report.apply();
                    }
                }
            }
        }
        ipv4_forward.apply();

        // bypass egress for now
        ig_tm_md.bypass_egress = 1;
    }
}

    /*********************  D E P A R S E R  ************************/

control IngressDeparser(packet_out pkt,
    /* User */
    inout my_ingress_headers_t                       hdr,
    in    my_ingress_metadata_t                      meta,
    /* Intrinsic */
    in    ingress_intrinsic_metadata_for_deparser_t  ig_dprsr_md)
{
    apply {
        pkt.emit(hdr);
    }
}


/*************************************************************************
 ****************  E G R E S S   P R O C E S S I N G   *******************
 *************************************************************************/

    /***********************  H E A D E R S  ************************/

struct my_egress_headers_t {
}

    /********  G L O B A L   E G R E S S   M E T A D A T A  *********/

struct my_egress_metadata_t {
}

    /***********************  P A R S E R  **************************/

parser EgressParser(packet_in        pkt,
    /* User */
    out my_egress_headers_t          hdr,
    out my_egress_metadata_t         meta,
    /* Intrinsic */
    out egress_intrinsic_metadata_t  eg_intr_md)
{
    /* This is a mandatory state, required by Tofino Architecture */
    state start {
        pkt.extract(eg_intr_md);
        transition accept;
    }
}

    /***************** M A T C H - A C T I O N  *********************/

control Egress(
    /* User */
    inout my_egress_headers_t                          hdr,
    inout my_egress_metadata_t                         meta,
    /* Intrinsic */    
    in    egress_intrinsic_metadata_t                  eg_intr_md,
    in    egress_intrinsic_metadata_from_parser_t      eg_prsr_md,
    inout egress_intrinsic_metadata_for_deparser_t     eg_dprsr_md,
    inout egress_intrinsic_metadata_for_output_port_t  eg_oport_md)
{
    apply {
        
    }
}

    /*********************  D E P A R S E R  ************************/

control EgressDeparser(packet_out pkt,
    /* User */
    inout my_egress_headers_t                       hdr,
    in    my_egress_metadata_t                      meta,
    /* Intrinsic */
    in    egress_intrinsic_metadata_for_deparser_t  eg_dprsr_md)
{
    apply {
        pkt.emit(hdr);
    }
}


/************ F I N A L   P A C K A G E ******************************/
Pipeline(
    IngressParser(),
    Ingress(),
    IngressDeparser(),
    EgressParser(),
    Egress(),
    EgressDeparser()
) pipe;

Switch(pipe) main;
