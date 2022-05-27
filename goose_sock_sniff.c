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

int main(int argc, uint8_t ** argv[])
{
	char opt[IFNAMSIZ] = "eth0";
	char message_data[BUFF_SIZE];
	int on = 1;
	int num_bytes, sock_sniff;
	sock_sniff = socket(AF_PACKET, SOCK_RAW, htons(0x88b8));
	setsockopt(sock_sniff, SOL_PACKET, SO_BINDTODEVICE, opt, IFNAMSIZ-1);

	while(1)
	{
		printf("Attempting to sniff");
		num_bytes = recvfrom(sock_sniff, message_data, BUFF_SIZE-1, 0, NULL, NULL);
		printf("Goose Packet Received");
	}
	return 0;
}
