#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <cjson/cJSON.h>

#include "standalone.h" 
#include "default.h"

#define BUFFER_SIZE 1024

/** 
 * This function reads a JSON configuration file, parses its contents, extracts 
 * configuration values, and stores them in the provided `configs` structure.
 * 
 * @param file_name The name of the configuration file to be parsed.
 * @param buffer A buffer where the contents of the configuration file will be stored temporarily.
 * @param configs A pointer to the `configs` structure.
 * 
 * @return void. This function modifies the `configs` structure based on the parsed configuration data.
 */
void parse_configs(char* file_name, char *buffer, struct configurations *configs) {
	// open the json file
	FILE *fp = fopen(file_name, "r");
	if (fp == NULL) {
		perror("Unable to open configuration file"); 
		exit(1);
	}
	// read the file contents into a string 
	int len = fread(buffer, 1, BUFFER_SIZE, fp);
	buffer[len] = '\0';
	fclose(fp);

	// parse the JSON data 
	cJSON *json = cJSON_Parse(buffer); 
	if (json == NULL) { 
		const char *error_ptr = cJSON_GetErrorPtr(); 
		if (error_ptr != NULL) { 
	    	 printf("Error when parsing json str: %s\n", error_ptr); 
	    } 
	    cJSON_Delete(json); 
	    exit(EXIT_FAILURE); 
	}
	
	// access the JSON data 
	cJSON *name = cJSON_GetObjectItemCaseSensitive(json, "server_ip_addr"); 
	if (cJSON_IsString(name) && (name->valuestring != NULL)) { 
	    strcpy(configs->server_ip_addr, name->valuestring);
	}

	name = cJSON_GetObjectItemCaseSensitive(json,"client_ip_addr"); 
	if (cJSON_IsString(name)) { 
		strcpy(configs->client_ip_addr, name->valuestring);
	}

	name = cJSON_GetObjectItemCaseSensitive(json, "client_port_SYN");
	if (cJSON_IsNumber(name)) { 
		configs->client_port_SYN = name->valueint;
	} else {
		configs->client_port_SYN = DEFAULT_CLIENT_PORT_SYN;
	}
	
	name = cJSON_GetObjectItemCaseSensitive(json,"server_port_head_SYN"); 
	if (cJSON_IsNumber(name)) { 
		configs->server_port_head_SYN = name->valueint;
	} else {
		configs->server_port_head_SYN = DEFAULT_SERVER_PORT_HEAD_SYN;
	}

    name = cJSON_GetObjectItemCaseSensitive(json,"server_port_tail_SYN"); 
	if (cJSON_IsNumber(name)) { 
		configs->server_port_tail_SYN = name->valueint;
	} else {
		configs->server_port_tail_SYN = DEFAULT_SERVER_PORT_TAIL_SYN;
	}
	
	name = cJSON_GetObjectItemCaseSensitive(json,"udp_src_port"); 
	if (cJSON_IsNumber(name)) { 
		configs->udp_src_port = name->valueint;
	} else {
		configs->udp_src_port = DEFAULT_UDP_SRC_PORT;
	}

	name = cJSON_GetObjectItemCaseSensitive(json,"udp_dst_port"); 
	if (cJSON_IsNumber(name)) { 
		configs->udp_dst_port = name->valueint;
	} else {
		configs->udp_dst_port = DEFAULT_UDP_DST_PORT;
	}

	name = cJSON_GetObjectItemCaseSensitive(json,"l");
	if (cJSON_IsNumber(name)) {
		configs->l = name->valueint;
	} else {
		configs->l = DEFAULT_L;
	}

	name = cJSON_GetObjectItemCaseSensitive(json,"n");
	if (cJSON_IsNumber(name)) {
		configs->n = name->valueint;
	} else {
		configs->n = DEFAULT_N;
	}

	name = cJSON_GetObjectItemCaseSensitive(json,"gamma"); 	
	if (cJSON_IsNumber(name)) {
		configs->gamma = name->valueint;
	} else {
		configs->gamma = DEFAULT_GAMMA;
	}

	name = cJSON_GetObjectItemCaseSensitive(json,"tau"); 	
	if (cJSON_IsNumber(name)) {
		configs->tau = name->valueint;
	} else {
		configs->tau = DEFAULT_TAU;
	}

    name = cJSON_GetObjectItemCaseSensitive(json,"ttl"); 	
	if (cJSON_IsNumber(name)) {
		configs->ttl = name->valueint;
	} else {
		configs->ttl = DEFAULT_TTL;
	}
	  
	// delete the JSON object 
	cJSON_Delete(json);  
}

/** 
 * This function checks if the configuration file is provided, then parses the configuration 
 * file, and execute the detection process by calling the `probe` function.
 * 
 * @param argc The number of command-line arguments.
 * @param argv An array of command-line arguments.
 * @return EXIT_SUCCESS on successful completion, or EXIT_FAILURE if an error occurs.
 */
int main(int argc, char* argv[]) {
    if (argc <= 1) {
		printf("Missing configurations. Exited early before detection. \n");
		exit(EXIT_FAILURE);
	}
    
	struct configurations configs;
	memset(&configs, 0, sizeof(struct configurations));
	char buffer[BUFFER_SIZE];
    char* file_name = argv[1];
	parse_configs(file_name, buffer, &configs);
	
    probe(&configs);
	
	return EXIT_SUCCESS;
}
