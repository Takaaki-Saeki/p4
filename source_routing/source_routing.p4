/* -*- P4_16 -*- */
#include <core.p4>
#include <v1model.p4>

const bit<16> TYPE_IPV4 = 0x800;
const bit<16> TYPE_SRCROUTING = 0x1234;

#define MAX_HOPS 9

/*headers*/
typedef bit<9>  egressSpec_t;
typedef bit<48> macAddr_t;
typedef bit<32> ip4Addr_t;

header ethernet_t {
    macAddr_t dstAddr;
    macAddr_t srcAddr;
    bit<16>   etherType;
}

header ipv4_t {
    bit<4>    version;
    bit<4>    ihl;
    bit<8>    diffserv;
    bit<16>   totalLen;
    bit<16>   identification;
    bit<3>    flags;
    bit<13>   fragOffset;
    bit<8>    ttl;
    bit<8>    protocol;
    bit<16>   hdrChecksum;
    ip4Addr_t srcAddr;
    ip4Addr_t dstAddr;
}

header srcRoute_t {
    bit<1> bos;
    bit<15> port;
}

struct metadata {
    /* empty */
}

struct headers {
    ethernet_t   ethernet;
    ipv4_t       ipv4;
    srcRoute_t[MAX_HOPS] srcRoutes;
}

/*parser*/
parser MyParser(packet_in packet,
                out headers hdr,
                inout metadata meta,
                inout standard_metadata_t standard_metadata) {

    state start {
        transition parse_ethernet;
    }

    state parse_ethernet {
         packet.extract(hdr.ethernet);
         transition select(hdr.ethernet.etherType) {
             TYPE_SRCROTING: trainsition parse_source_routing;
             default: accept;
         }
    }

    state parse_source_routing {
        packet.extract(hdr.srcRoutes.next){
            trainsition select(hdr.srcRoutes.last.bos) {
                1: parse_ipv4;
                default: accept;
            }
        }
    }

    state parse_ipv4 {
        packet.extract(hdr.ipv4);
        transition accept;
    }
}

/*checksum verification*/
control MyVerifyChecksum(inout headers hdr, inout metadata meta) {
    apply {  }
}

/*ingress processing*/
control MyIngress(inout headers hdr,
                  inout metadata meta,
                  inout standard_metadata_t standard_metadata) {
    action drop() {
        mark_to_drop();
    }

    action srcRoute_nhop() {
        standard_metadata.egress_spec = (bit<9>)hdr.srcRoutes[0].port;
        hdr.srcRoutes.pop_front(1);
    }

    action srcRoute_finish() {
        hdr.ethernet.etherType = TYPE_IPV4;
    }

    action update_ttl(){
        hdr.ipv4.ttl = hdr.ipv4.ttl - 1;
    }

    apply {
        if(hdr.srcRoutes[0].isValid()){
            if(hdr.srcRoutes[0].bos==1){
                srcRoute_finish();
            }
            srcRoute_nhop();
            if(hdr.ipv4.isValid()){
                update_ttl();
            }else{
                drop();
            }
        }
    }
}

/*egress processing*/
control MyEgress(inout headers hdr,
                 inout metadata meta,
                 inout standard_metadata_t standard_metadata) {
    apply {  }
}

/*checksum computation*/
control MyComputeChecksum(inout headers hdr, inout metadata meta) {
    apply { }
}

/*deparser*/
control MyDeparser(packet_out packet, in headers hdr) {
    apply {
        packet.emit(hdr.ethernet);
        packet.emit(hdr.srcRoutes);
        packet.emit(hdr.ipv4);
    }
}

/*switch*/
V1Switch(
MyParser(),
MyVerifyChecksum(),
MyIngress(),
MyEgress(),
MyComputeChecksum(),
MyDeparser()
) main;
