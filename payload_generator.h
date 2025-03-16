#include <stdint.h>

void generate_random_bytes(unsigned char *, int);

unsigned char * generate_payload(int, int);

void fill_packet_id(unsigned char *, uint16_t);
