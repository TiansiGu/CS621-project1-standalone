#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netdb.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <pthread.h>

#include "standalone.h"
#include "payload_generator.h"


int populate_ip_header(struct ip *iphr, struct configurations *configs, int data_size) {
	iphr->ip_v = 4; //ipv4
	iphr->ip_hl = 5; //set ip header size to be the minimum: 5*4 = 20 bytes
	iphr->ip_tos = 0; //type of service
	iphr->ip_len = iphr->ip_hl * 4 + data_size; //no payload
	iphr->ip_id = htonl(54321); //all datagrams between src and dst of a given protocol must have unique IPv4 ID over a period of MDL
	iphr->ip_off = htons(IP_DF);  //set don't fragment bit
	iphr->ip_ttl = configs->ttl; //TTL is a single byte, no need to convert endian
	iphr->ip_p = IPPROTO_TCP; //equivalent to 6
	iphr->ip_sum = 0; //set to 0 before computing the actual checksum later

	struct hostent *host = gethostbyname("localhost");
    if (host == NULL) {
        perror("Could not get host information for localhost \n");
        return -1;
    }
	iphr->ip_src.s_addr = *(unsigned long *)(host->h_addr_list[0]); /* addr in hostent struct are already in network byte order */
	iphr->ip_dst.s_addr = inet_addr(configs->server_ip_addr); /* inet_addr returns value in network byte order */
	return 0;
}

void populate_tcp_header(struct tcphdr *tcphr, uint16_t dst_port) {
	tcphr->th_sport = htons(1234); /* arbitrary port */
  	tcphr->th_dport = htons(dst_port);
	tcphr->th_seq = random(); /* start from random sequence number */
	tcphr->th_ack = 0; /* the ack sequence is 0 in the 1st packet */
	tcphr->th_x2 = 0;  /* reserved field */
	tcphr->th_off = 5; /* set the tcp hdr length to be minimum value 20 bytes, as no options */
	tcphr->th_flags = TH_SYN; /* SYN packet */
	tcphr->th_win = htons(65535); /* max allowed window size, doesn't matter as receiver only sends RST back */
	tcphr->th_sum = 0;
	tcphr->th_urp = 0; /* urgent pointer is not used for this app */
}

int send_SYN(int sock_syn, struct configurations *configs, uint16_t server_port) {
	struct tcphdr tcphr;
	populate_tcp_header(&tcphr, server_port);
	
	struct ip iphr;
	int res = populate_ip_header(&iphr, configs, tcphr.th_off * 4); //no payload, data_size is only tcp header size
	if (res == -1) {
		printf("Create ip header failed \n");
		return -1;
	}

	char buffer[iphr.ip_len]; // initialize buffer for sending
	memcpy(buffer, &iphr, iphr.ip_hl * 4); // copy ip header
	char *tcp_ptr = buffer + iphr.ip_hl * 4;
	memcpy(tcp_ptr, &tcphr, tcphr.th_off * 4); // copy tcp header

	// Set IP_HDRINCL option
	int one = 1;
    res = setsockopt(sock_syn, IPPROTO_IP, IP_HDRINCL, &one, sizeof(one));
    if (res == -1) {
		perror("Warning: Cannot set HDRINCL!");
		return -1;
	}

	// create sin used in sendto func
	struct sockaddr_in sin;
	sin.sin_family = AF_INET;
	sin.sin_addr.s_addr = inet_addr(configs->server_ip_addr);
	sin.sin_port = htons(server_port);

	// send SYN packet
	res = sendto(sock_syn, buffer, iphr.ip_len, 0, 
		(struct sockaddr *) &sin, sizeof(sin));
	if (res == -1) {
		perror("Failed to send SYN packet");
		return -1;
	}
    
	return 0;
}

void *send_detect_packets(void *arg) {
	struct configurations *configs = (struct configurations *) arg;

	int sock_syn = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);
	if (sock_syn == -1) {
	    perror("SYN socket creation failed");
	    exit(EXIT_FAILURE);
	}
	
	int sock_udp = socket(AF_INET, SOCK_RAW, IPPROTO_UDP);
	if (sock_udp == -1) {
		perror("UDP socket creation failed");
		exit(EXIT_FAILURE);
	}

	// Send head SYN
	int result = send_SYN(sock_syn, configs, configs->server_port_head_SYN);
	if (result == -1) {
		printf("Failed to send head SYN packet \n");
		close(sock_syn);
		close(sock_udp);
	}
	
	close(sock_syn);
	close(sock_udp);
	printf("Sender thread done \n");
	return NULL;
}

void *receive_RST_packets(void *arg) {

	printf("Receiver thread done \n");
	return NULL;
}

void probe(struct configurations *configs) {
	unsigned char *low_entropy_payload = generate_payload(configs->l, 0);
	unsigned char *high_entropy_payload = generate_payload(configs->l, 1);

	pthread_t sender_thr, listener_thr;
	// create sender thread
	int sender_thr_result = pthread_create(&sender_thr, NULL, send_detect_packets, configs);
	if (sender_thr_result != 0) {
		perror("Error occurred when creating sender thread");
		exit(EXIT_FAILURE);
	}

	// create listener thread
	int listener_thr_result = pthread_create(&listener_thr, NULL, receive_RST_packets, configs);
	if (listener_thr_result != 0) {
		perror("Error occurred when creating listener thread");
		exit(EXIT_FAILURE);
	}

	// Wait for both of the threads to finish
	pthread_join(sender_thr, NULL);
	pthread_join(listener_thr, NULL);


	printf("Detection completed! \n");
}
