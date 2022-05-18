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
	printf("%2x",(hmac[1] | (hmac[0] << 4)));
	return (uint8_t)(hmac[1] | (hmac[0] << 4));
}

void parseMac(uint8_t * mac, struct ether_header *eth, 	struct sockaddr_ll socket_address)
{
	for(int i = 0; i < 6; i++)
	{
		uint8_t hmac[2] = {0,0};
		hmac[0] = mac[i*2];
		hmac[1] = mac[(i*2)+1];
		uint8_t temp_mac = asciiToHex(hmac);
		eth->ether_dhost[i] = temp_mac;
		socket_address.sll_addr[i] = temp_mac;
	}
}

void main(int argc, uint8_t* argv[])
{
	//struct bpf_aux_data     aux_data;
	int sock; 
	int send_length = 0;	
	char send_buffer[BUFSIZE];
	struct ether_header *eth = (struct ether_header *) send_buffer;
	struct sockaddr_ll socket_address;
	struct ifreq iface_mac;
	char iface_name[IFNAMSIZ];
	char DMAC[12] = {"010ccd010012"};


	//Can we open a socket
 	sock = socket(AF_PACKET, SOCK_RAW, IPPROTO_RAW);
 	//This will be used for reception of VLAN packets
 	//sock.setsockopt(SOL_PACKET, PACKET_AUXDATA);
	
	if(argc > 1)
	{
		strcpy(iface_name, argv[1]);
	}
	else
	{
		strcpy(iface_name, DEFAULT_IFACE);
	}

	memset(&iface_mac, 0, sizeof(struct ifreq));
	strncpy(iface_mac.ifr_name, iface_name, IFNAMSIZ-1);
		
	memset(send_buffer, 0, BUFSIZE);

	if(argc > 2)
	{
		strcpy(DMAC, argv[2]);
	}
		
	parseMac(DMAC, eth, socket_address);

	socket_address.sll_ifindex = iface_mac.ifr_ifindex;
	socket_address.sll_halen = ETH_ALEN;
	
	for(int i = 0; i < 6; i++)
	{
		eth->ether_shost[i] = ((uint8_t *)&iface_mac.ifr_hwaddr.sa_data)[i];
	}	
	
	eth->ether_type = htons(0x88B8);
	
	
	send_length += sizeof(struct ether_header);
	
	send_buffer[send_length++] = 0x00;
	send_buffer[send_length++] = 0x00;
	send_buffer[send_length++] = 0x00;
	send_buffer[send_length++] = 0x00;
	send_buffer[send_length++] = 0x00;
	send_buffer[send_length++] = 0x00;

	if (ioctl(sock, SIOCGIFINDEX, &iface_mac) < 0)
	    perror("SIOCGIFINDEX");

	if (ioctl(sock, SIOCGIFHWADDR, &iface_mac) < 0)
	    perror("SIOCGIFHWADDR");

	if (sendto(sock, send_buffer, send_length, 0, (struct sockaddr*)&socket_address, sizeof(struct sockaddr_ll)) == -1)
	{
		perror("send");
	}
}

