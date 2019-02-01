/* -*- P4_16 -*- */
#include <core.p4>
#include <v1model.p4>

const bit<16> TYPE_IPV4 = 0x800;

/*headers*/
typedef bit<9> egressSpec_t;
typedef bit<48> macAddr_t;
typedef bit<32> ipv4Addr_t;

header ethernet_t {
    macAddr_t dstAddt;
    macAddr_t srcAddr;
    bit<16> etherType;
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

header myTunnel_t {
    bit<16> proto_id;
    bit<16> dst_id;
}

struct metadata {}

struct headers {
    ethernet_t ethernet;
    ipv4_t ipv4;
    myTunnel_t myTunnel;
}

/*parser*/
parser MyParser(packet_in packet,
                out headers hdr,
                inout metadata meta,
                inout standard_metadata_t standard_metadata){
    start{
        transition ethernet_parser;
        accept;
    }

    state ethernet_parser {
        packet.extract(hdr.ethernet);
        transition select(hdr.ethernet.etherType){
            0x0800: tunnel_parser;
            default: accept;
        }
    }

    state tunnel_parser {
        packet.extract(hdr.myTunnel);
        transition select(hdr.myTunnel.proto_id){
            TYPE_IPV4: ipv4_parser;
            default accept;
        }
    }

    state ipv4_parser {
        packet.extract(hdr.ipv4);
        accept;
    }
}

control MyVerifyChecksum(inout headers hdr, inout metadata meta) {
    apply {  }
}

control MyIngress(inout headers hdr,
                  inout metadata meta,
                  inout standard_metadata_t standard_metadata) {
    action drop() {
        mark_to_drop();
    }

    action ipv4_forward(macAddr_t dstAddr, egressSpec_t port) {
        standard_metadata.egress_spec = port;
        hdr.ipv4.srcAddr = hdr.ipv4.dstAddr;
        hdr.ipv4.dstAddr = dstAddr;
        hdr.ipv4.ttl = hdr.ipv4.ttl - 1;
    }

    table ipv4_lpm {
        key = {
            hdr.ipv4.dstAddr: lpm;
        }
        actions = {
            ipv4_forward;
            drop;
            NoAction;
        }
        size=1024;
        default_action = drop();
    }

    action myTunnel_forward(egressSpec_t port) {
        standard_metadata.egress_spec = port;
    }

    table myTunnel_exact {
        key = {
            hdr.myTunnel.dst_id: exact;
        }

        actions = {
            myTunnel_forward;
            drop;
        }
        size = 1024;
        default_action = drop();
    }

    apply {
        if(hdr.myTunnel.isValid()){
            myTunnel_forward;
        }else if(hdr.ipv4.isValid()){
            ipv4_forward();
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
control MyComputeChecksum(inout headers  hdr, inout metadata meta) {
    apply {
        update_checksum(
            hdr.ipv4.isValid(),
            { hdr.ipv4.version,
              hdr.ipv4.ihl,
              hdr.ipv4.diffserv,
              hdr.ipv4.totalLen,
              hdr.ipv4.identification,
              hdr.ipv4.flags,
              hdr.ipv4.fragOffset,
              hdr.ipv4.ttl,
              hdr.ipv4.protocol,
              hdr.ipv4.srcAddr,
              hdr.ipv4.dstAddr },
              hdr.ipv4.hdrChecksum,
              HashAlgorithm.csum16);
    }
}

/*deparser*/
control MyDeparser(packet_out packet, in headers hdr){
    apply {
        packet.emit(hdr.ethernet);
        packet.emit(hdr.myTunnel);
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






