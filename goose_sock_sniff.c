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

#define BUFF_SIZE  1500

void getEthtype(char * message_data)
{
	struct ether_header *eth = (struct ether_header *) message_data;
	uint16_t type = eth->ether_type;
	//uint16_t temp = type;
	type = (type << 8) | (type >> 8);
	if(type == 0x88b8)
	{
		printf("Goose Received. Endpoint:");
		char * helper = (char *)&eth->ether_dhost;
		for(int i = 0; i < 6; i++)
		{
		printf("%02x",helper[i]);
		}
		printf("\n");
		fflush(stdout);
	}

}

int main(int argc, uint8_t ** argv[])
{
	struct packet_mreq mreq;
	memset(&mreq,0,sizeof(mreq));
	char * opt= "eth0";
	char message_data[BUFF_SIZE];
	int on = 1;
	int num_bytes, sock_sniff, val;
	unsigned int len;
	struct ifreq iface_mac;
	val = 1;
	len = sizeof(val);
	sock_sniff = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
	setsockopt(sock_sniff, SOL_PACKET, PACKET_AUXDATA, &on, sizeof(on));
	//setsockopt(sock_sniff, SOL_SOCKET, SO_BINDTODEVICE, "eth0", 4) >= 0 ? :	perror("binding failed");


	memset(&iface_mac, 0, sizeof(struct ifreq));
	strncpy(iface_mac.ifr_name, "eth0", IFNAMSIZ-1);
	iface_mac.ifr_ifindex = if_nametoindex(opt);
	mreq.mr_ifindex = iface_mac.ifr_ifindex;
	mreq.mr_type = PACKET_MR_PROMISC;
	mreq.mr_alen = 6;

	setsockopt(sock_sniff, SOL_PACKET,PACKET_ADD_MEMBERSHIP, (void*)&mreq, (socklen_t)sizeof(mreq));
	ioctl(sock_sniff, SIOCGIFHWADDR, &iface_mac) >= 0 ? : perror("SIOCGIFHWADDR");
	ioctl(sock_sniff, SIOCGIFINDEX, &iface_mac) >= 0 ? : perror("SIOCGIFINDEX");
	printf("Attempting to sniff");
	while(1)
	{
		num_bytes = recv(sock_sniff, message_data, BUFF_SIZE-1, 0);
		getEthtype(message_data);
	}
	return 0;
}
