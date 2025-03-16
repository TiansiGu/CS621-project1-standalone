#include <stdlib.h>
#include <stdio.h>
#include <pthread.h>

#include "standalone.h"
#include "payload_generator.h"

void *send_detect_packets(void *arg) {

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
