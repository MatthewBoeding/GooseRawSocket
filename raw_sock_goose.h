#include <stdint.h>

#define GOOSE_PDU_TAG               0x61 
#define GOCBREF_TAG                 0x80 
#define TIMEALLOWEDTOLIVE_TAG       0x81 
#define DATASET_TAG                 0x82 
#define GOID_TAG                    0x83 
#define TIMESTAMP_TAG               0x84 
#define STATE_TAG                   0x85 
#define SEQUENCE_TAG                0x86 
#define TEST_TAG                    0x87 
#define CONFREV_TAG                 0x88 
#define NDSCOM_TAG                  0x89 
#define NUMDATSETENTRIES_TAG        0x8A 

 
#define GOOSE_BOOLEAN_TAG           0x83 
#define GOOSE_BITSTRING_TAG         0x84 
#define GOOSE_INTEGER_TAG           0x85 
#define GOOSE_UINT_TAG              0x86 
#define GOOSE_FLOAT_TAG             0x87 
#define GOOSE_REAL_TAG              0x88 
#define GOOSE_OCTETSTRING_TAG       0x89 
#define GOOSE_VISIBLESTRING_TAG     0x8A 
#define GOOSE_UTCTIME_TAG           0x8C 
#define GOOSE_BCD_TAG               0x8D 
#define GOOSE_BOOLEANARR_TAG        0x8E 
#define GOOSE_OBJECTID_TAG          0x8F 
#define GOOSE_UTF8STRING_TAG        0x90 
#define GOOSE_STRUCT_TAG            0x2A 


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

