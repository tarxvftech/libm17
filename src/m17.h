#ifndef __m17_h
#define __m17_h

#define m17_callsign_alphabet " ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-/."
#define M17_STREAM_PREFIX 0x4D313720

/*
 * An IP Frame is different than an RF frame, and includes a full LICH every frame, and one M17 frame per UDP packet.
 * Payload is as specified for M17 RF frames.

32b  "M17 " in ascii, useful for multiplexing with other modes - 0x4D313720 as an int, M17_STREAM_PREFIX here
		Big endian like everything else, first character in the packet is going to be that 'M'
16b  random streamid, must change every PTT to differentiate streams
224b Full LICH without sync:
        48b  Address dst
        48b  Address src
        16b  int(M17_Frametype)
        112b nonce (for encryption)
16b  Frame number counter - 15 unsigned bits for counting, top bit indicates it's the last frame in a stream (end of PTT)
128b payload
16b  CRC-16 chksum

*/

// TODO : overhaul all structs. not interested in maintaining an IPLICH and an RFLICH and etc etc etc


//all structures must be big endian on the wire, so you'll want htonl (man byteorder 3) and such. 
typedef struct __attribute__((__packed__)) _LICH {
	uint8_t  addr_dst[6]; //48 bit int - you'll have to assemble it yourself unfortunately
	uint8_t  addr_src[6];  
	uint16_t frametype; //frametype flag field per the M17 spec
	uint8_t  nonce[14]; //bytes for the nonce
} M17_LICH; 
#define LICH_sz 28
//without SYNC or other parts

typedef struct __attribute__((__packed__)) _RFLICH {
	M17_LICH lich;
	uint16_t crc;
} M17_RFLICH; 
#define RFLICH_sz 30

typedef struct __attribute__((__packed__)) _ip_frame {
	uint32_t magic;
	uint16_t streamid;		
	M17_LICH lich; 
	uint16_t framenumber;	
	uint8_t  payload[16]; 	
	uint16_t crc;

} M17_IPFrame;
#define IPFrame_sz LICH_sz+26

typedef struct __attribute__((__packed__)) _rf_frame {
	uint8_t  lich_chunk[6]; //LICH_sz / x == 6
	uint16_t framenumber;	
	uint8_t  payload[16]; 	
	uint16_t crc;

} M17_RFFrame;
#define RFFrame_sz LICH_sz+20

uint64_t m17_callsign2addr( const char * callsign );
uint64_t encode_callsign_base40(const char *callsign);
void m17_set_addr(uint8_t * dst, uint64_t address);
void init_lich(M17_LICH * lich, 
		uint64_t dst, 
		uint64_t src, 
		uint16_t frametype, 
		char * nonce);
void init_ipframe(M17_IPFrame * pkt,
		uint16_t streamid,
		uint64_t dst,
		uint64_t src,
		uint16_t frametype,
		char *   nonce,
		uint16_t framenumber,
		uint8_t* payload
		);
void init_rfframe(M17_IPFrame * pkt,
		M17_LICH * lich,
		uint16_t framenumber,
		uint8_t* payload
		);
//void copy_lich_chunk(uint8_t * dest, M17_LICH * src, int chunkidx);
//void copy_rflich_chunk(uint8_t * dest, M17_RFLICH * src, int chunkidx);
void explain_frame(); 
int indexOf(const char * haystack, char needle);


//CRC stuff from M17_UDP repo, SP5WWP commits
#define M17_CRC_POLY 0x5935
void m17_crc_lut_gen(uint16_t *crc_table, uint16_t poly);
uint16_t m17_calc_crc(const uint16_t*crc_table, const uint8_t* message, uint16_t nBytes);
uint16_t m17_calc_crc_ez( uint8_t * data, size_t len );

#endif
