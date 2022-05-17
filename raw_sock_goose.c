#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/ether.h>
#include <net/if.h>
#include <stdint.h>
#include <stdio.h>

#define DEFAULT_IFACE "eth0"

uint8_t asciiToHex(uint8_t * hmac)
{
	for(int j = 0; j <2; j++)
	{
		char ascii = hmac[j];			
		if(ascii > 0x30 && ascii < 0x67)
		{
			if(ascii < 0x40)
			{
				ascii &= 0x0F;
			}
			else if((ascii > 0x40 && ascii < 0x47) || (ascii > 0x60 && ascii < 0x67)
			{
				ascii = (ascii + 9) & 0x0F;
			}
			else
			{
				perror("invalid mac");
			}
		}
		else
		{
			perror("invalid mac");
		}
		hmac[j] = ascii;
	}
	return hmac[0] | (hmac[1] << 4);
}

void parseMac(uint8_t * mac, int def)
{
	if(def)
	{
		eh->ether_shost[0] = ((uint8_t *)&if_mac.ifr_hwaddr.sa_data)[0];
		eh->ether_shost[1] = ((uint8_t *)&if_mac.ifr_hwaddr.sa_data)[1];
		eh->ether_shost[2] = ((uint8_t *)&if_mac.ifr_hwaddr.sa_data)[2];
		eh->ether_shost[3] = ((uint8_t *)&if_mac.ifr_hwaddr.sa_data)[3];
		eh->ether_shost[4] = ((uint8_t *)&if_mac.ifr_hwaddr.sa_data)[4];
		eh->ether_shost[5] = ((uint8_t *)&if_mac.ifr_hwaddr.sa_data)[5];
	}
	else
	{
		for(int i = 0; i < 6; i++)
		{
			char hmac[2] = {0,0};
			hmac[0] = mac[i*2];
			hmac[i] = mac[(i*2)+1];
			eh->ether_shost[i] = asciiToHex(&hmac);
		}
	}
}

void main(int argc, char* argv[])
{
	//struct bpf_aux_data     aux_data;
	int sock; 
	int send_length = 0;	
	struct ether_header *eth = (struct ether_header *) sendbuf;
	struct sockaddr_ll socket_address;
	struct ifreq if_mac;
	char if_name[IFNAMSIZ];
	uint8_t DMAC[12] = {"010ccd010012"};
	
	//Can we open a socket
 	sock = socket(AF_PACKET, SOCk_RAW, IPPROTO_RAW));
 	//This will be used for reception of VLAN packets
 	sock.setsockopt(SOL_PACKET, PACKET_AUXDATA);
	if(sock == -1)
	{
		perror("socket");
	}
	
	memset(&if_mac, 0, sizeof(struct ifreq));
	strncpy(if_mac.ifr_name, ifName, IFNAMSIZ-1);
	
	if(argc > 1)
	{
		strcpy(iface_name, argc[1]);
	}
	else
	{
		strcpy(iface_name, DEFAULT_IFACE);
	}
	
	if(argc > 2)
	{
		parseMac(argc[2], 0);
	}
	else
	{
		parseMac("", 1);
	}
	
	if(argc > 3)
	{
		DMAC = argc[3];
	}

	
	for(int i = 0; i < 6; i++)
	{
		char hmac[2] = {0,0};
		hmac[0] = argc[i*2];
		hmac[i] = argc[(i*2)+1];
		eh->ether_dhost[i] = asciiToHex(&hmac);
	}	
	
	eh->ether_type = htons(0x88B8);
	
	
	send_length += sizeof(struct ether_header);
	
	sendto(sock, send_buffer, send_length, 0, (struct sockaddr*)&socket_address, sizeof(struct sockaddr_ll))
}

