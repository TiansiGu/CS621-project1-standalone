#include "standalone.h"
#include "payload_generator.h"

void probe(struct configurations *configs) {
	unsigned char *low_entropy_payload = generate_payload(configs->l, 0);
	unsigned char *high_entropy_payload = generate_payload(configs->l, 1);
}
