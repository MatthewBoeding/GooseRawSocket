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
#include <wiringPi.h>
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

int ber_encode(char tag, char * data, int length, char * buffer)
{
	int i = 0;
	buffer[i++] = tag;
	if(length > 128)
	{
		length > 256 ? buffer[i++] = 0x81 : buffer[i++] = 0x82;
		buffer[i++] = (uint8_t)length >> 8;
	}
	buffer[i++] = (uint8_t) length;
	for(int j = 0; j < length; j++)
	{
		buffer[i+j] = data[j];
	}
	return i;
}

void craft_packet(char * buffer)
{
	struct goose_apdu * apdu = (struct goose_apdu *) buffer;
	int idx = sizeof(goose_apdu);
	int pdu_length = 0;
	char temp_buff[BUFF_SIZE];
	char * current_index = &temp_buff;
	apdu->appid = 0x0009;
	apdu->reserved1 = 0x0000;
	apdu->reserved2 = 0x0000;
	apdu->pdu_tag = GOOSE_PDU_TAG;
	
	char goosefloat[] = {0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
	pdu_length += ber_encode(GOOSE_FLOAT_TAG, &goosefloat, 8, current_index);
	current_index += pdu_length;
	char boolean = 0x00;
	pdu_length += ber_encode(GOOSE_BOOLEAN_TAG, &boolean, 1, current_index);
	
	apdu->length;
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

	
	if(argc < 2)
	{
		printf("No parameters passed...using defaults")
	}
	else
	{
		params = fopen(argv[1], 'r'); 
	}
	char * file_buffer = (char *)malloc(3000 * sizeof(char)));

 	line_size = getline(&file_buffer, 3000, params);
	char * current_file = file_buffer + line_size;
	indexes[count++] = line_size;
	while(line_size >= 0)
	{
		line_size = getline(&current_file, 3000, params);
		indexes[count] = line_size + indexes[count-1];
		count++;
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

