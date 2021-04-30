/* -*- P4_16 -*- */

#include <core.p4>
#include <tna.p4>

/*************************************************************************
 ************************** D E F I N E S ********************************
**************************************************************************/
#define DCNC_ID 0x3950
#define DCNC_READ_REQUEST               1
#define DCNC_WRITE_REQUEST              2
#define DCNC_READ_REPLY                 3
#define DCNC_WRITE_REPLY                4
#define DCNC_CACHE_HIT                  5
#define DCNC_VALUE_WIDTH                32

/*************************************************************************
 ************* C O N S T A N T S    A N D   T Y P E S  *******************
**************************************************************************/
typedef bit<48> mac_addr_t;
typedef bit<16> ether_type_t;
typedef bit<32> ipv4_addr_t;
typedef bit<8> ip_proto_t;
typedef bit<16> l4_port_t;

const ether_type_t ETHERTYPE_IPV4 = 16w0x0800;
const ether_type_t ETHERTYPE_ARP = 16w0x0806;
const ether_type_t ETHERTYPE_DECAY_UPDATE = 16w0x8888;

const ip_proto_t IP_PROTO_ICMP = 1;
const ip_proto_t IP_PROTO_TCP = 6;
const ip_proto_t IP_PROTO_UDP = 17;

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

header icmp_h {
    bit<8> type_;
    bit<8> code;
    bit<16> hdr_checksum;
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

header apphdr_h {
    bit<16> id;
}

header dcnc_h {
    bit<8>  op;
    bit<48> key;
    bit<DCNC_VALUE_WIDTH> value;
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
    apphdr_h apphdr;
    dcnc_h  dcnc;
}

struct tor_ser_md_t {
    bit<17> index;
    bit<1>  exist;
    bit<1>  is_valid;
    mac_addr_t  ethernet_addr;
    ipv4_addr_t ipv4_addr;
    l4_port_t   udp_port;
}

    /******  G L O B A L   I N G R E S S   M E T A D A T A  *********/

struct my_ingress_metadata_t {
    tor_ser_md_t tor_ser;
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
        meta.src_port = 0;
        meta.dst_port = 0;
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
        transition accept;
    }

    state parse_apphdr {
        pkt.extract(hdr.apphdr);
        transition select(hdr.apphdr.id) {
            DCNC_ID : parse_dcnc;
            default : accept;
        }
    }

    state parse_dcnc {
        pkt.extract(hdr.dcnc);
        transition accept;
    }
}

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

    action tor_ser_cache_check_act(bit<17> index) {
        meta.tor_ser.index = index;
        meta.tor_ser.exist = 1;
    }

    table tor_ser_cache_check {
        key = {
            hdr.dcnc.key: exact;
        }
        actions = {
            tor_ser_cache_check_act;
        }
        size = 131072;
    }

    action tor_ser_copy_header_act() {
        meta.tor_ser.ethernet_addr = hdr.ethernet.src_addr;
        meta.tor_ser.ipv4_addr = hdr.ipv4.src_addr;
        meta.tor_ser.udp_port = hdr.udp.src_port;
    }

    Register<bit<1>,_>(131072) tor_ser_valid_reg;
    RegisterAction<bit<1>, _, bit<1>> (tor_ser_valid_reg) tor_ser_valid_reg_read = {
        void apply(inout bit<1> val, out bit<1> rv) {
            rv = val;
        }
    };
    RegisterAction<bit<1>, _, bit<1>> (tor_ser_valid_reg) tor_ser_valid_reg_clear = {
        void apply(inout bit<1> val, out bit<1> rv) {
            val = 0;
            rv = 0;
        }
    };
    RegisterAction<bit<1>, _, bit<1>> (tor_ser_valid_reg) tor_ser_valid_reg_set = {
        void apply(inout bit<1> val, out bit<1> rv) {
            val = 1;
            rv = 1;
        }
    };

    action tor_ser_valid_check_act () {
        meta.tor_ser.is_valid = tor_ser_valid_reg_read.execute(meta.tor_ser.index);
    }

    action tor_ser_valid_clear_act () {
        meta.tor_ser.is_valid = tor_ser_valid_reg_clear.execute(meta.tor_ser.index);
    }

    action tor_ser_valid_set_act () {
        meta.tor_ser.is_valid = tor_ser_valid_reg_set.execute(meta.tor_ser.index);
    }

    Register<bit<32>,_>(131072) tor_ser_value_reg;
    RegisterAction<bit<32>, _, bit<32>> (tor_ser_value_reg) tor_ser_value_reg_read = {
        void apply(inout bit<32> val, out bit<32> rv) {
            rv = val;
        }
    };
    RegisterAction<bit<32>, _, bit<32>> (tor_ser_value_reg) tor_ser_value_reg_update = {
        void apply(inout bit<32> val, out bit<32> rv) {
            val = hdr.dcnc.value;
            rv = val;
        }
    };

    action tor_ser_value_read_act () {
        hdr.dcnc.value = tor_ser_value_reg_read.execute(meta.tor_ser.index);

        // Exchange src with dst 
        hdr.ethernet.src_addr = hdr.ethernet.dst_addr;
        hdr.ethernet.dst_addr = meta.tor_ser.ethernet_addr;
        hdr.ipv4.src_addr = hdr.ipv4.dst_addr;
        hdr.ipv4.dst_addr = meta.tor_ser.ipv4_addr;
        hdr.udp.src_port = hdr.udp.dst_port;
        hdr.dst_port = meta.tor_ser.udp_port;

        // Set op
        hdr.dcnc.op = DCNC_CACHE_HIT;
    }

    action tor_ser_value_update_act () {
        tor_ser_value_reg_write.execute(meta.tor_ser.index);
    }

    action drop() {
        ig_dprsr_md.drop_ctl = 0x0;    // drop packet
        exit;
    }

    action l2_forward(PortId_t port) {
        ig_tm_md.ucast_egress_port = port;
    }

    table tor_ser_route_l2 {
        key =  {
            hdr.ethernet.dst_addr: exact;
        }
        actions = {
            l2_forward;
            drop();
        }
        default_action=  drop();
        size= 1024;
    }

    apply {
        if(hdr.dcnc.isValid()) {
            tor_ser_cache_check.apply();
            tor_ser_copy_header_act();
            if(meta.tor_ser.exist == 1) {
                if(hdr.dcnc.op == DCNC_READ_REQUEST) {
                    tor_ser_valid_check_act();
                } else if (hdr.dcnc.op == DCNC_WRITE_REQUEST) {
                    tor_ser_valid_clear_act();
                } else if (hdr.dcnc.op == DCNC_WRITE_REPLY || hdr.dcnc.op == DCNC_READ_REPLY) {
                    tor_ser_valid_set_act();
                }
            }

            if (meta.tor_ser_md.is_valid == 1) {
                if (hdr.dcnc.op == DCNC_READ_REQUEST) {
                    tor_ser_value_read_act();
                } else if (hdr.dcnc.op == DCNC_WRITE_REPLY || hdr.dcnc.op == DCNC_READ_REPLY) {
                    apply (tor_ser_value_update);
                }
            }
        }

        tor_ser_route_l2.apply();
        
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
