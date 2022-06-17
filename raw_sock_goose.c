#include <errno.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/ioctl.h>
#include <netinet/ether.h>
#include <netinet/in.h>
#include <net/if.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <linux/if_packet.h>
#include <unistd.h>
#include "raw_sock_goose.h"

#define BUFSIZE  1500
#define DEFAULT_IFACE "eth0"

uint8_t asciiToHex(uint8_t * hmac)
{
	for(int j = 0; j <2; j++)
	{
		uint8_t ascii = hmac[j];			
		if(ascii >= 0x30 && ascii < 0x67)
		{
			if(ascii < 0x40)
			{
				ascii &= 0x0F;
			}
			else if((ascii > 0x40 && ascii < 0x47) || (ascii > 0x60 && ascii < 0x67))
			{
				ascii = (ascii + 9) & 0x0F;
			}
			else
			{
				perror("mac second check");
			}
		}
		else
		{
			perror("mac first check");
		}
		hmac[j] = ascii;
	}
	return (uint8_t)(hmac[1] | (hmac[0] << 4));
}

void parseMac(uint8_t * mac, struct ether_header *eth, 	struct sockaddr_ll socket_address, int dest)
{
	for(int i = 0; i < 6; i++)
	{
		uint8_t hmac[2] = {0,0};
		hmac[0] = mac[i*2];
		hmac[1] = mac[(i*2)+1];
		uint8_t temp_mac = asciiToHex(hmac);
		if(dest > 0)
		{
			eth->ether_dhost[i] = temp_mac;
			socket_address.sll_addr[i] = temp_mac;
		}
		else
		{
			eth->ether_shost[i] = temp_mac;
		}
	}
}

uint64_t goose_timestamp()
{
	uint64_t timestamp;
	struct timespec time;
	clock_gettime(CLOCK_REALTIME, &time);
	unsigned int frac = 500000000;
	unsigned int nsec = time.tv_nsec;
	
	timestamp = time(NULL) << 32;
	
	for(int i = 0; i < 24; i++)
	{
		if(time.tv_nsec > frac)
		{
			timestamp |= 1 << (i + 8);
			time.tv_nsec = time.tv_nsec - frac;
		}
		frac = frac / 2; 
	}
	timestamp |= 0x18;
	return timestamp;
}

int ber_encode(char tag, char * data, uint16_t length, char * buffer)
{
	int i = 0;
	*buffer++ = tag;
	i++;
	if(length >= 128)
	{
		//Will need to test...i think i confused myself with this
		/*if(length >= 16777216)
		{
			*buffer++ = 0x84;
			*buffer++ = (uint8_t) length >> 24;
			*buffer++ = (uint8_t)length >> 16;
			*buffer++ = (uint8_t)length >> 8;
			i += 4;
		}
		if(16777216 >= length >= 65536)
		{
			*buffer++ = 0x83;
			*buffer++ = (uint8_t)length >> 16;
			*buffer++ = (uint8_t)length >> 8;
			i += 3;
		}*/
		if(length >= 256)
		{
			*buffer++ = 0x82;
			*buffer++ = (uint8_t)length >> 8;
			i += 2;
		} else
		{
			*buffer++ = 0x81;
			i++;
		}
	}
	*buffer++ = (uint8_t) length;
	i++;
	for(int j = 0; j < length; j++)
	{
		buffer[i+j] = data[j];
	}
	i += length;
	return i;
}
int goose_build_pduheader(char * data_buffer, char * current_index, struct goose_indices * data_indices)
{
	uint16_t ber_length = 0;
	uint16_t pdu_length = 0;
	uint16_t idx = sizeof(struct goose_apdu);
	uint16_t * curr_idx = (uint16_t *) &data_indices;
	uint16_t * next_idx = curr_idx++;

	for(uint16_t i = GOCBREF_TAG; i <= NUMDATSETENTRIES_TAG; i++)
	{
		//we'll generate a correct timestamp
		if(i != TIMESTAMP_TAG)
		{
			//so GOID index will need to reference stnum index
			if(i == GOID_TAG)
			{
				*next_idx++;
			}
			//how far between indexed entries
			idx_len = *next_idx - *curr_idx;
			//update the current index
			*curr_idx++ = idx + pdu_length;
			ber_length = ber_encode(GOCBREF_TAG, &data_buffer, idx_len, current_index);	
			current_index += ber_length;
			pdu_length += ber_length;
			data_buffer += idx_len;
			next_idx++;
		}
		else
		{
			//generate our timestamp
			uint64_t timestamp = goose_timestamp();
			char * tstamp_ptr = (char *) &timestamp;
			*curr_idx++ = idx + ber_length;
			ber_length = ber_encode(TIMESTAMP_TAG, tstamp_ptr, 4, current_index);
			current_index += ber_length;			
			pdu_length += ber_length;
		}
	}
	return pdu_length;
}


void goose_args(char * packet_buffer, char * data_buffer, struct goose_indices * data_indices)
{
	//static values
	int pdu_length = 0;
	int ber_length = 0;
	int pdu_length_size = 0;
	uint16_t idx_len = 0;
		
	//dynamic values	
	char * temp_buff = (char *)(malloc(BUF_SIZE)*sizeof(char));
	char * current_index = temp_buff;
	struct goose_apdu * apdu = (struct goose_apdu *) packet_buffer;
	int idx = sizeof(struct goose_apdu);
	int num_entries = data_buffer[(int)(data_indices.numdatasetentries_index)];

	//data_buffer: |appid|gocbref|tat|dataset|goid|stnum|sqnum|test|confref|ndscom|#dataset|datatype,len,data|
	//Build APDU header
	apdu->appid = (uint16_t)((*data_buffer++<<8 | *(data_buffer++));
	apdu->reserved1 = 0x0000;
	apdu->reserved2 = 0x0000;
	apdu->pdu_tag = GOOSE_PDU_TAG;
	
	//Build PDU header:
	pdu_length = goose_build_pduheader(data_buffer, current_index, data_indices);
	
	//We don't know alldata (tag 0xAB) length yet, calculate that
	int data_length = 0;
	char * numdata_buff = (char *) malloc(256 * sizeof(char));
	
	//encode our data:
	for(int i = 0; i < num_entries; i++)
	{
		char * data_loc = &(current_index) + (2*sizeof(char));
		char * len_loc = &(current_index) + (1*sizeof(char));
		ber_length = ber_encode(*current_index, &data_loc, &len_loc, numdata_buff); 
		current_index += ber_length;			
		pdu_length += ber_length;
		data_length += ber_length;
	}
	
	//Now we can finish the PDU header
	*current_buffer++ = ALLDATA_TAG;
	pdu_length++;
	if(data_length >= 256)
	{		
		*current_buffer++ = 0x82;
		*current_buffer++ = (char)data_length >> 8;
		pdu_length += 2;
	}else if(pdu_length >= 128)
	{
			*current_buffer++ = 0x81;
			pdu_length++;
	}
	*current_buffer++ = (char)data_length;
	pdu_length++;
	
	//But, the data needs to be put in our correct buffer
	for(i = 0; i < data_length; i++)
	{
		*current_buffer++ = *numdata_buff++;
	}
	
	//So, we can calculate total pdu length
	current_buffer = &packet_buffer + sizeof(goose_apdu);
	if(pdu_length >= 256)
	{		
		*current_buffer++ = 0x82;
		*current_buffer++ = (char)pdu_length >> 8;
		pdu_length_size += 2;
	}else if(pdu_length >= 128)
	{
			*current_buffer++ = 0x81;
			pdu_length_size++;
	}
	*current_buffer++ = (char)pdu_length;
	pdu_length_size++;
	
	//Reserved1&2 + pdu tag are added for apdu length
	apdu->length = pdu_length+pdu_length_size+5;

	//The APDU header is complete. All that is left is to finish packet generation
	for(int i=0; i < pdu_length; i++)
	{
		*current_buffer++ = *temp_buff++; 
	}
	
	//And update packet indexes for future use
	curr_idx = (uint16_t *) &data_indices;
	for(uint16_t i = GOCBREF_TAG; i <= NUMDATSETENTRIES_TAG; i++)
	{
		*curr_idx += pdu_length_size;
		curr_idx++;
	}
	free(temp_buff);
	return;
}

void default_goose_args(char * packet_buffer, struct goose_indices * data_indices)
{
	int idx;
	char * data_buffer = (char *) malloc(BUFSIZE * sizeof(char));
	char * encoding_buffer = data_buffer;
	//data_buffer: |appid|gocbref|tat|dataset|goid|stnum|sqnum|test|confref|ndscom|#dataset|datatype,len,data|
	char appid[2] = 0x1012;
	strcpy(encoding_buffer, appid);
	encoding_buffer += 2;	
	idx += 2;
	
	char gocbRef[22] = "HPLSCFG/LLN0$GO$GPub01";
	data_indices.gocbref_index = idx;
	strcpy(encoding_buffer, gocbRef);
	encoding_buffer += 22;	
	idx += 22;
	
	char tat[2] = 0x07d0;
	data_indices->timeallowed_index = idx;
	strcpy(encoding_buffer, tat);
	encoding_buffer += 2;	
	idx += 2;
	
	char datSet[21] = "HPLSCFG/LLN0$URDSet01";
	data_indices->dataset_index = idx;
	strcpy(encoding_buffer, datSet);
	encoding_buffer += 21;	
	idx += 21;
	
	char goID[8] = "Feeder_1";
	data_indices->goid_index = idx;
	strcpy(encoding_buffer, goID);
	encoding_buffer += 8;	
	idx += 8;
	
	char zero = 0x00;
	data_indices->state_index = idx;
	*encoding_buffer++ = zero;
	idx++;
	
	data_indices->sequence_index = idx;
	*encoding_buffer++ = zero;
	idx++;
	
	data_indices->test_index = idx;
	*encoding_buffer++ = zero;
	idx++;
	
	data_indices->confrev_index = idx;
	*encoding_buffer++ = 0x01;
	idx++;
	
	data_indices->numdatasetentries_index = idx;
	char numDat = 0x03;
	*encoding_buffer++ = numDat;
	
	char data[14] = {0x87,0x05, 0x80, 0x00, 0x00, 0x00, 0x00, 0x83, 0x01, 0x00, 0x84, 0x02, 0x06, 0x40};
	strcpy(encoding_buffer, data);
	encoding_buffer += 14;
	
	goose_args(packet_buffer, data_buffer, data_indices);
	free(data_buffer);
}

int connect_socket()
{
	//Open Socket
 	sock = socket(AF_PACKET, SOCK_RAW, IPPROTO_RAW);
	//Make non-blocking calls
	setsockopt(sock, SOL_SOCKET, SO_DONTROUTE, (void *)&on, len) >= 0? : perror("Socket Routing"); 
	//interface association
	strcpy(iface_name, DEFAULT_IFACE);
	memset(&iface_mac, 0, sizeof(struct ifreq));
	strncpy(iface_mac.ifr_name, iface_name, IFNAMSIZ-1);
		
	memset(send_buffer, 0, BUFSIZE);
	memset(&socket_address, 0, sizeof(struct sockaddr_ll));	
	ioctl(sock, SIOCGIFHWADDR, &iface_mac) >= 0 ? : perror("SIOCGIFHWADDR");
	ioctl(sock, SIOCGIFINDEX, &iface_mac) >= 0 ? : perror("SIOCGIFINDEX");
	
	socket_address.sll_family = AF_PACKET;
	socket_address.sll_ifindex = iface_mac.ifr_ifindex;
}

void main(int argc, uint8_t* argv[])
{
	int sock,iface_idx, line_size; 
	int send_length = 0;	
	int indexes[20];
	int count = 0;
	char send_buffer[BUFSIZE];
	struct ether_header *eth = (struct ether_header *) send_buffer;
	struct sockaddr_ll socket_address;
	struct ifreq iface_mac;

	int on = 1;
	char iface_name[IFNAMSIZ];
	char DMAC[12] = {"010ccd010001"};
	char SMAC[12] = {0x00};
	unsigned int len = sizeof(on);
	FILE *params;
	char goose_buffer[BUFSIZE];
	
	if(argc < 2)
	{
		printf("No parameters passed...using defaults");
		default_goose_args(&goose_buffer);
	}
	else
	{
		params = fopen(argv[1], 'r'); 
		char * file_buffer = (char *)malloc(3000 * sizeof(char)));

		line_size = getline(&file_buffer, 3000, params);
		char * current_file = file_buffer + line_size;
		indexes[count++] = line_size;
		while(line_size >= 0)
		{
			line_size = getline(&current_file, 3000, params);
			indexes[count] = line_size + indexes[count-1];
			indexes[count] <= 2500 ? : line_size = -1;
			count++;
			current_file += line_size;
		}
		current_file = file_buffer;
		parse_goose_args(&current_file, &indexes, count);
		free(file_buffer);
	}

	if(SMAC[0] == 0x00)
	{
		for(int i = 0; i < 6; i++)
		{
			eth->ether_shost[i] = ((uint8_t *)&iface_mac.ifr_hwaddr.sa_data)[i];
		}
	}

	sock = connect_socket();

	parseMac(DMAC, eth, socket_address, 1);	
	eth->ether_type = htons(0x88B8);
	
	int eth_hdr_len = sizeof(struct ether_header);
	send_length += eth_hdr_len;

	for(int g = 0; g < sizeof(goose_buffer); g++)
	{ 
		send_buffer[eth_hdr_len+g] = goose_buffer[g];
	}
	send_length += sizeof(goose_buffer);
	while(1)
	{
		for(int i = 0; i < 10; i++)
		{
			sendto(sock, send_buffer, send_length, MSG_DONTWAIT, (struct sockaddr*)&socket_address, sizeof(struct sockaddr_ll));// >= 0 ? : perror("sending"); 
		}
	}
	close(sock);
}

