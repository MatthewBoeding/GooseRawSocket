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

void main(int argc, uint8_t* argv[])
{
	int sock,iface_idx; 
	int send_length = 0;	
	char send_buffer[BUFSIZE];
	struct ether_header *eth = (struct ether_header *) send_buffer;
	struct sockaddr_ll socket_address;
	struct ifreq iface_mac;
	
	//This is all added for vlan fun; 
	
	struct vlan_data aux_data;
	struct iovec  iov;
	struct msghdr msg;
	struct cmsghdr *cmsg;
	union {
		struct cmsghdr cmsg;
		char buf[CMSG_SPACE(sizeof(struct tpacket_auxdata))];
	}cmsg_buf;
	int on = 1;
	char iface_name[IFNAMSIZ];
	char DMAC[12] = {"010ccd010001"};
	char SMAC[12] = {""};

	
	//Can we open a socket
 	sock = socket(AF_PACKET, SOCK_RAW, IPPROTO_RAW);
 	//This will be used for reception of VLAN packets
 	setsockopt(sock, SOL_PACKET, PACKET_AUXDATA, &on, sizeof(on));
	
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
	memset(&socket_address, 0, sizeof(struct sockaddr_ll));	
	ioctl(sock, SIOCGIFHWADDR, &iface_mac) >= 0 ? : perror("SIOCGIFHWADDR");
	ioctl(sock, SIOCGIFINDEX, &iface_mac) >= 0 ? : perror("SIOCGIFINDEX");
	
	socket_address.sll_family = AF_PACKET;
	socket_address.sll_ifindex = iface_mac.ifr_ifindex;
	

	if(argc > 2)
	{
		strcpy(DMAC, argv[2]);
	}
	if(argc > 3)
	{
		strcpy(SMAC, argv[3]);
		parseMac(SMAC, eth, socket_address, 0);
	}
	else
	{
		for(int i = 0; i < 6; i++)
		{
			eth->ether_shost[i] = ((uint8_t *)&iface_mac.ifr_hwaddr.sa_data)[i];
		}
	}	
	parseMac(DMAC, eth, socket_address, 1);	
	eth->ether_type = htons(0x88B8);
	
	
	send_length += sizeof(struct ether_header);
	
	send_buffer[send_length++] = 0x00;
	send_buffer[send_length++] = 0x00;
	send_buffer[send_length++] = 0x00;
	send_buffer[send_length++] = 0x00;
	send_buffer[send_length++] = 0x00;
	send_buffer[send_length++] = 0x00;

	if (sendto(sock, send_buffer, send_length, 0, (struct sockaddr*)&socket_address, sizeof(struct sockaddr_ll)) == -1)
	{
		perror("send");
	}
	close(sock);
}
