#ifndef COMPDETECT_CONFIG_PARSER_H
#define COMPDETECT_CONFIG_PARSER_H

struct compdetect_config
{
    char server_ip_addr[16];
    int udp_src_port;
    int udp_dest_port;
    int tcp_head_syn_dest_port;
    int tcp_tail_syn_dest_port;
    int tcp_dest_port;
    int udp_payload_size;
    int inter_measurement_time;
    int udp_packet_count;
    int udp_packet_ttl;
};

struct compdetect_config *
parse_json_string (const char *json_str);

#endif /* COMPDETECT_CONFIG_PARSER_H */