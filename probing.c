#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netdb.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <fcntl.h>
#include <errno.h>
#include <pthread.h>

#include "standalone.h"
#include "payload_generator.h"

#define RECV_BUFF_SIZE 4096
#define CUTOFF_TIME 60

struct tcp_pseudo_header {
    u_int32_t src_address;
    u_int32_t dst_address;
    u_int8_t placeholder;
    u_int8_t protocol;
    u_int16_t tcp_length;
	struct tcphdr tcp;
};

/* this function generates header checksums */
unsigned short csum(unsigned short *buf, int nwords) {
  unsigned long sum;
  for (sum = 0; nwords > 0; nwords--)
    sum += *buf++;
  sum = (sum >> 16) + (sum & 0xffff);
  sum += (sum >> 16);
  return ~sum;
}

int populate_ip_header(struct ip *iphr, struct configurations *configs, int protocol, int data_size) {
	iphr->ip_v = 4; //ipv4
	iphr->ip_hl = 5; //set ip header size to be the minimum: 5*4 = 20 bytes
	iphr->ip_tos = 0; //type of service
	iphr->ip_len = iphr->ip_hl * 4 + data_size; //no payload
	iphr->ip_id = htonl(54321); //all datagrams between src and dst of a given protocol must have unique IPv4 ID over a period of MDL
	iphr->ip_off = htons(IP_DF);  //set don't fragment bit
	iphr->ip_ttl = configs->ttl; //TTL is a single byte, no need to convert endian
	iphr->ip_p = protocol; //tcp is 6, udp is 17
	iphr->ip_sum = 0; //set to 0 before computing the actual checksum later

    // unsigned long src_addr;
    // if (get_host_addr(&src_addr) == -1) return -1; /* get host real ip addr*/
	iphr->ip_src.s_addr = inet_addr("192.168.128.4"); /* addr in hostent struct are already in network byte order */
	iphr->ip_dst.s_addr = inet_addr(configs->server_ip_addr); /* inet_addr returns value in network byte order */
	
	// Calculate and set the IP header checksum
    iphr->ip_sum = csum((unsigned short *)iphr, sizeof(struct ip) >> 1);
	
	return 0;
}

void populate_tcp_header(struct tcphdr *tcphr, struct ip *iphr, uint16_t dst_port) {
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

	// Use tcp pseudo header to calculate checksum
	struct tcp_pseudo_header psh;
    // Fill in tcp pseudo header
    psh.src_address = iphr->ip_src.s_addr;  // Source IP address
    psh.dst_address = iphr->ip_dst.s_addr;    // Destination IP address
    psh.placeholder = 0;                        // Reserved, always 0
    psh.protocol = IPPROTO_TCP;                 // Protocol number (TCP = 6)
    psh.tcp_length = htons(sizeof(struct tcphdr)); 
	memcpy(&(psh.tcp), tcphr, sizeof(struct tcphdr));
    
    /* Calculate the checksum and fill it in */
    tcphr->th_sum = csum((unsigned short*)&psh, sizeof(struct tcp_pseudo_header) >> 1);
}

int send_SYN(int sock_syn, struct configurations *configs, uint16_t server_port) {
	struct ip iphr;
	int res = populate_ip_header(&iphr, configs, IPPROTO_TCP, sizeof(struct tcphdr)); //no payload, data_size is only tcp header size
	if (res == -1) {
		printf("Create ip header failed for tcp SYN \n");
		return -1;
	}

	struct tcphdr tcphr;
	populate_tcp_header(&tcphr, &iphr, server_port);
	
	//tcphr.th_sum = tcp_checksum(&tcphr, &iphr, 0); // set checksum in tcp header

	char* buffer = malloc(iphr.ip_len); // initialize buffer for sending
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
    free(buffer);
	return 0;
}

void bind_port(int fd, int port, struct sockaddr_in *addr) {
	addr->sin_family = AF_INET;
    addr->sin_addr.s_addr = INADDR_ANY;
    addr->sin_port = htons(port);

	if (bind(fd, (struct sockaddr*) addr, sizeof(struct sockaddr_in)) == -1) {
		perror("Failed to bind socket");
		close(fd);
		exit(EXIT_FAILURE);
	}
}

int send_UDP_train(int sock_udp, struct configurations *configs, 
	struct sockaddr_in *server_sin, int high) {
	// Generate udp payload
	unsigned char *payload = generate_payload(configs->l, high);

	// Send packet train
	int count;
	for (int i = 0; i < configs->n; i++) {
		fill_packet_id(payload, i);
		count = sendto(sock_udp, payload, configs->l, 0, (struct sockaddr *) server_sin, sizeof(struct sockaddr_in));
		if (count == -1) {
			perror("Failed to send UDP packets with low entropy data");
			free(payload);
			return -1;
		}
	}
	free(payload); //free allocated resource
	return 0;
}

void *send_detect_packets(void *arg) {
	struct configurations *configs = (struct configurations *) arg;

	int sock_syn = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);
	if (sock_syn == -1) {
	    perror("SYN raw socket creation failed");
	    exit(EXIT_FAILURE);
	}
	
	int sock_udp = socket(AF_INET, SOCK_DGRAM, 0);
	if (sock_udp == -1) {
		perror("UDP socket creation failed");
		exit(EXIT_FAILURE);
	}

	// Create client and server addr for sending udp train
	struct sockaddr_in client_sin, server_sin;
	memset(&client_sin, 0, sizeof(client_sin));
	memset(&server_sin, 0, sizeof(server_sin));

	in_addr_t server_addr = inet_addr(configs->server_ip_addr);

    server_sin.sin_family = AF_INET; /* address from Internet, IP address specifically */
	server_sin.sin_addr.s_addr = server_addr; /* already in network order */
	server_sin.sin_port = htons(configs->udp_dst_port); /* convert to network order */

	// Specify the port client uses to connect to server
	bind_port(sock_udp, configs->udp_src_port, &client_sin);

	// Send head SYN
	int result = send_SYN(sock_syn, configs, configs->server_port_head_SYN);
	if (result == -1) {
		printf("Failed to send head SYN packet \n");
		close(sock_syn);
		close(sock_udp);
	}
	// Send UDP trains
	result = send_UDP_train(sock_udp, configs, &server_sin, 0);
	if (result == -1) {
		printf("Failed to send low entropy udp train \n");
		close(sock_syn);
		close(sock_udp);
	}
	// Send tail SYN 
	result = send_SYN(sock_syn, configs, configs->server_port_tail_SYN);
	if (result == -1) {
		printf("Failed to send head SYN packet \n");
		close(sock_syn);
		close(sock_udp);
	}

	sleep(configs->gamma);

	// Send head SYN
	result = send_SYN(sock_syn, configs, configs->server_port_head_SYN);
	if (result == -1) {
		printf("Failed to send head SYN packet \n");
		close(sock_syn);
		close(sock_udp);
	}
	// Send UDP trains
	result = send_UDP_train(sock_udp, configs, &server_sin, 1);
	if (result == -1) {
		printf("Failed to send low entropy udp train \n");
		close(sock_syn);
		close(sock_udp);
	}
	// Send tail SYN 
	result = send_SYN(sock_syn, configs, configs->server_port_tail_SYN);
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

void set_nonblocking(int fd) {
	int flags = fcntl(fd, F_GETFL, 0);
	if (flags == -1) {
        perror("Failed to get file status flags by fcntl F_GETFL");
        exit(EXIT_FAILURE);
    }
	int result = fcntl(fd, F_SETFL, flags | O_NONBLOCK);
	if (result == -1) {
        perror("Failed to set O_NONBLOCK flag");
		close(fd);
        exit(EXIT_FAILURE);
    }
}

void *receive_RST_packets(void *arg) {
	struct configurations *configs = (struct configurations *) arg;

	int sock = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);
	if (sock == -1) {
	    perror("RST listener raw socket creation failed");
	    exit(EXIT_FAILURE);
	}

	// Assign address to socket
	struct sockaddr_in sender_sin;
	memset(&sender_sin, 0, sizeof(sender_sin));
	sender_sin.sin_family = AF_INET;
	sender_sin.sin_addr.s_addr = inet_addr(configs->server_ip_addr);

	// Set non-blocking
	set_nonblocking(sock);

	unsigned char buf[RECV_BUFF_SIZE];

	int k = 0;
	int count;
	struct timespec t_l1, t_ln, t_h1, t_hn, t_curr;
	socklen_t sin_len = sizeof(sender_sin);
	while (1) {
		// sender addr is sent in to filter the received packets
        count = recvfrom(sock, buf, RECV_BUFF_SIZE, 0, 
			(struct sockaddr *) &sender_sin, &sin_len);
        if (count == -1) {
			if (errno == EAGAIN || errno == EWOULDBLOCK) {
				clock_gettime(CLOCK_MONOTONIC, &t_curr);
				if (k > 0 && t_curr.tv_sec - t_l1.tv_sec > CUTOFF_TIME) {
					printf("Time out, terminated here. k = %d\n", k);
					break;
				} else {
					continue; // No data available (non-blocking)
				}
			} else {
				perror("Recvfrom failed");
            	close(sock);
				exit(EXIT_FAILURE);
			}  
        }

		k++;
		if (k == 1) clock_gettime(CLOCK_MONOTONIC, &t_l1);

		// parse received buffer
		// differentiate RST for head and tail by port number, and the 2rd train's RSTs are after the 1st
		// ToDo!
		

		if (k == 4) {
			printf("Received RST packets done \n");
			break;
		}
	}

	printf("Receiver thread done \n");
	return NULL;
}

void probe(struct configurations *configs) {
	//unsigned char *low_entropy_payload = generate_payload(configs->l, 0);
	//unsigned char *high_entropy_payload = generate_payload(configs->l, 1);

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
