#include <core.p4>
#include <spectrum_model.p4>
#include <spectrum_actions.p4>
#include <spectrum_headers.p4>
#include "parser.p4"

const EthernetAddress smac = 48w0x248a072fde56;
const EthernetAddress dmac = 48w0x5cf9dd6c5e88;
const IPv4Address src_ip = 32w0x0c0c0c02;
const IPv4Address dest_ip = 32w0x0c0c0c64;
const label_port_t analyzer = 16w0x04;
const bit is_truncated = 1;
const bit<16> truncation_size = 0x60;
const vlan_id_t vid = 1;

control control_in_port(inout Headers_t headers, inout metadata_t meta, inout standard_metadata_t standard_metadata){
    apply{}
}

control control_in_rif(inout Headers_t headers, inout metadata_t meta, inout standard_metadata_t standard_metadata){
    apply{}
}

control control_out_rif(inout Headers_t headers, inout metadata_t meta, inout standard_metadata_t standard_metadata){
    apply{}
}


control control_out_port(inout Headers_t headers, inout metadata_t meta, inout standard_metadata_t standard_metadata){

    //action and table for simple mirroring
    action DoMirror(label_port_t analyzer_port) {
        mirror_to_remote_l3_egress_v2(analyzer_port, is_truncated, truncation_size, dmac, smac, dest_ip, src_ip, vid, 0);
        hit_counter();
    }
    
    table table_mirror {
        key = {
                headers.ip.ipv4.diffserv : exact;
        }
        actions = {
            DoMirror;
            NoAction; 
        }
        default_action = NoAction();

        const entries ={
            (0x1a): DoMirror(analyzer); 
        }
    }
	

    table ipv4_check_checksum {
	key = { 
		standard_metadata.egress_port : exact;
		headers.ip.ipv4.hdr_checksum : ternary;
        }
	actions = {
	   DoMirror;
           NoAction;
       }
       size = 1024;
       default_action = NoAction();
    }	
    apply {
            if (headers.ip.ipv4.isValid()) {
                table_mirror.apply();
				ipv4_check_checksum.apply();
            }
        }   
}


SpectrumSwitch(
    MirrorParser(),
    control_in_port(),
    control_in_rif(),
    control_out_rif(),
    control_out_port(),
    MirrorDeparser()
    ) main;
