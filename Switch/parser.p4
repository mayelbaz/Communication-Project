// Parser Defintion file.
// Defines how stream of bytes
// that enters the switch,
// get parsed into meaningful packets.


struct metadata_t {
    // TODO - user metadata, with USER TOKEN
    @mlnx_extract("FLEX_ACL_KEY_USER_TOKEN")
    bit<12> METADATA_REG ;
}

// Structure of parsed headers
struct Headers_t
{
    Ethernet_h ethernet;
    Vlan_h     vlan;

    IP_h       ip;
    Mpls_h     mpls;
 //   Grh_h      grh;
    Fcoe_h     fcoe;
    Arp_h      arp;
    Ptp_h      ptp;
    Control_h  ctl;
    Raw_h      raw;

    Ah_h       ah;
    Esp_h      esp;
    Icmp_v4_h  icmp4;
    Icmp_v6_h  icmp6;
    Bth_h      bth;
    Gre_h      gre;
    Tcp_h      tcp;
    Udp_h      udp;
}

// Parser section
// This describes the default parser graph state machine for the
// Spectrum architecture
parser MirrorParser(packet_in p,
                 out Headers_t headers,
                 inout metadata_t meta,
                 inout standard_metadata_t standard_metadata)
{
    state start
    {
        p.extract(headers.ethernet);
        transition select(headers.ethernet.ether_type)
        {
            TYPE_VLAN : parse_vlan;
            TYPE_IPV4 : parse_ipv4;    // 16w0x800
            TYPE_IPV6 : parse_ipv6;    // 16w0x86DD
            TYPE_ARP  : parse_arp;
            TYPE_PTP  : parse_ptp;
            TYPE_MPLS : parse_mpls;
            TYPE_CONTROL : parse_control;

            // other parser states go here
            // default : reject;
            default : parse_raw;
        }
    }

    state parse_vlan {
        p.extract(headers.vlan);
        transition select(headers.vlan.ether_type) {
            TYPE_IPV4 : parse_ipv4;
            TYPE_IPV6 : parse_ipv6;    // 16w0x86DD
            TYPE_ARP  : parse_arp;
            TYPE_PTP  : parse_ptp;
            TYPE_MPLS : parse_mpls;
            TYPE_CONTROL : parse_control;
            default: accept;
        }
    }

    state parse_ipv4
    {
        p.extract(headers.ip.ipv4);
        verify(headers.ip.ipv4.version == 4w4, error.IPv4IncorrectVersion);
        verify(headers.ip.ipv4.ihl == 4w5, error.IPv4OptionsNotSupported);
        transition select(headers.ip.ipv4.protocol)
        {
            TCP_PROTOCOL : parse_tcp;
            UDP_PROTOCOL : parse_udp;
            // custom parser states go here

            // no default rule: all other packets rejected
            default : accept;
        }
    }

    state parse_ipv6
    {
        p.extract(headers.ip.ipv6);
        transition accept;
    }

    state parse_arp
    {
        //p.extract(headers.arp);
        transition accept;
    }

    state parse_tcp
    {
        p.extract(headers.tcp);
        transition accept;
    }

    state parse_udp
    {
        p.extract(headers.udp);
        transition select(headers.udp.dst_port)
        {
            default: accept;
        }
    }

    state parse_geneve { transition accept; }
    state parse_vxlan { transition accept; }
    state parse_ptp { transition accept; }
    state parse_mpls { transition accept; }
    state parse_control { transition accept; }
    state parse_raw { transition accept; }
}


control MirrorDeparser(inout Headers_t headers, packet_out b) {
    apply {
        b.emit(headers.ethernet);
        b.emit(headers.vlan);
        b.emit(headers.ip.ipv4);
        b.emit(headers.udp);
        b.emit(headers.tcp);
    }
}

