#include <stdint.h>

struct goose_apdu{
	uint16_t appid;
	uint16_t length;
	uint16_t reserved1;
	uint16_t reserved2;
	uint8_t pdu_tag;
};

struct vlan_data{
	uint16_t vlan_tag;
	uint16_t vlan_tag_present;
};

