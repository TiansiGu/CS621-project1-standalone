#include <stdint.h>
#define ADDR_LEN 32

struct configurations {
	char server_ip_addr[ADDR_LEN];
	uint16_t server_port_head_SYN;
    uint16_t server_port_tail_SYN;
	uint16_t udp_src_port;
	uint16_t udp_dst_port;
	uint32_t l; // the Size of the UDP Payload in a UDP Packet
	uint32_t n; // the Number of Packets in the UDP Packet Train
	uint16_t gamma; // inter-measurement time, γ
	uint16_t tau; // threshold of time diff (in millis) between low and high entropy data
    uint16_t ttl; // TTL for the UDP Packets, used to trace the location of compression link 
};

void probe(struct configurations *);
