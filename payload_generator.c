#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <netinet/in.h>
#include <unistd.h>
#include <fcntl.h>

#include "payload_generator.h"

/** 
* This function opens "/dev/urandom", reads the requested number of random bytes,
* and writes them to the provided buffer.
* 
* @param ptr The buffer to store the generated random bytes.
* @param size The number of random bytes to generate.
*/
void generate_random_bytes(unsigned char *ptr, int size) {
	int randomData = open("/dev/urandom", O_RDONLY);
	if (randomData < 0) {
		perror("Cannot open /dev/urandom");
		exit(EXIT_FAILURE);
	}

	/** "/dev/urandom" can return fewer bytes than you've asked for when there is not 
	enough bytes. Solution: Keep reading until the requested size is received. */
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

/**
 * This function creates a buffer of the specified size, fills it with random bytes
 * or zeroes depending on the value of `entropy_high`. The first 2 bytes are reserved
 * for the packet ID, which will be filled by the `fill_packet_id` function.
 * 
 * @param size The total size of the payload (including the 2-byte packet ID).
 * @param entropy_high indicating whether to fill the payload with random data (1) or zeroes (0).
 * @return A pointer to the generated payload.
 */
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

/**
 * This function takes a packet ID, converts it to network byte order (Big Endian),
 * and stores it at the beginning of the provided buffer. The size of the packet ID
 * is 2 bytes (16 bits).
 * 
 * @param data_ptr The buffer where the packet ID will be written.
 * @param packet_id The packet ID to be written (in host byte order).
 */
void fill_packet_id(unsigned char *data_ptr, uint16_t packet_id) {
	uint16_t network_packet_id = htons(packet_id);
	memcpy(data_ptr, &network_packet_id, sizeof(network_packet_id));
}
