#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <netinet/in.h>
#include <unistd.h>
#include <fcntl.h>

#include "payload_generator.h"

void generate_random_bytes(unsigned char *ptr, int size) {
	int randomData = open("/dev/urandom", O_RDONLY);
	if (randomData < 0) {
		perror("Cannot open /dev/urandom");
		exit(EXIT_FAILURE);
	}

	/** "/dev/urandom" can return fewer bytes than you've asked for when there is not 
	enough bytes. Solution: Keep reading until the requested size is fully received. */
	size_t randomDataLen = 0;
	while (randomDataLen < size) {
		ssize_t read_bytes = read(randomData, ptr + randomDataLen, size - randomDataLen);
		if (read_bytes < 0) {
			perror("Failed to read in random bytes");
			close(randomData);
			exit(EXIT_FAILURE);
		}
		randomDataLen += read_bytes;
	}

	close(randomData);
}

unsigned char * generate_payload(int size, int entropy_high) {
	unsigned char *data_ptr = malloc(size);
	if (data_ptr == NULL) {
		perror("Failed to allocate memory for UDP packet data");
		exit(EXIT_FAILURE);
	}
	
	data_ptr += sizeof(uint16_t); // move ptr to the start of low/high entropy data

	if (entropy_high) {
		generate_random_bytes(data_ptr, size - sizeof(uint16_t)); //the first 2 bytes (16 bits) are reserved for packet ID
	} else {
		memset(data_ptr, 0, size - sizeof(uint16_t));
	}
	return data_ptr - sizeof(uint16_t);
}

void fill_packet_id(unsigned char *data_ptr, uint16_t packet_id) {
	uint16_t network_packet_id = htons(packet_id);
	memcpy(data_ptr, &network_packet_id, sizeof(network_packet_id));
}
