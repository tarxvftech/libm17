#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <arpa/inet.h>

#include "m17.h"


#define tcolBlack  "\u001b[30m"
#define tcolRed  "\u001b[31m"
#define tcolGreen  "\u001b[32m"
#define tcolYellow  "\u001b[33m"
#define tcolBlue  "\u001b[34m"
#define tcolMagenta  "\u001b[35m"
#define tcolCyan  "\u001b[36m"
#define tcolWhite  "\u001b[37m"
#define tcolReset  "\u001b[0m"


int indexOf(const char * haystack, char needle){
	char * sp = strchr( haystack, needle);
	if( sp == NULL ){ 
		return -1; 
	} 
	return (int)(sp-haystack);
}

 
uint64_t m17_callsign2addr( const char * callsign ){
	uint64_t encoded = 0;
	int clen = strlen(callsign)-1; //skip the null byte
	for( int i = clen; i >= 0; i-- ){
		//yes, this is slower even than the reference implementation - but it's easier to modify, a good thing for our test bed.
		//(and it's not noticeably slower in the practical sense for a full PC)
		int charidx = indexOf(m17_callsign_alphabet,callsign[i]);
		if( charidx == -1 ){
			//replace invalid characters with spaces
			charidx = 0;
		}
		encoded *= 40;
		encoded += charidx;
		if( encoded >= 262144000000000 ){ //40**9
			//invalid callsign
			return -1;
		}
	}
	return encoded;
}
uint64_t encode_callsign_base40(const char *callsign) {
	//straight from the spec, unedited and unchecked
	uint64_t encoded = 0;
	for (const char *p = (callsign + strlen(callsign) - 1); p >= callsign; p-- ) {
		encoded *= 40;

		// If speed is more important than code space, you can replace this with a lookup into a 256 byte array.
		if (*p >= 'A' && *p <= 'Z'){  // 1-26
			encoded += *p - 'A' + 1;
		} else if (*p >= '0' && *p <= '9'){  // 27-36
			encoded += *p - '0' + 27;
		} else if (*p == '-'){  // 37
			encoded += 37;
		} else if (*p == '/'){  // 38
			encoded += 38;
		// This . is just a place holder. Change it if it makes more sense, 
		// Be sure to change them in the decoder too.
		} else if (*p == '.'){  // 39
			encoded += 39;
		} else{
			// Invalid character or a ' ', represented by 0. (which gets decoded to ' ')
			;
		}
	}
	return encoded;
}



void m17_set_addr(char * dst, uint64_t address){
	for( int i = 0,j=5; i < 6 ; i++, j--){
		dst[j] = (address>>(i*8)) & 0xff;
		/*
		bbbbbb = iiii iiii
		     ^           ^
		   <<|         <<| 
		     -------------
		*/
	}
}
void init_lich(M17_LICH * lich,
		uint64_t dst,
		uint64_t src,
		uint16_t frametype,
		char * nonce
		){
	char * lich_as_bytes = (char *) lich;
	memset( lich_as_bytes, 0, sizeof(M17_LICH));
	m17_set_addr(lich->addr_src, src);
	m17_set_addr(lich->addr_dst, dst);
	lich->frametype = htons(frametype);
	memset(lich->nonce, *nonce, 14);
}
void init_ipframe(M17_IPFrame * pkt,
		uint16_t streamid,
		uint64_t dst,
		uint64_t src,
		uint16_t frametype,
		char *   nonce,
		uint16_t framenumber,
		char* payload
		){
	char *pkt_as_bytes = (char *) pkt;
	memset(pkt_as_bytes, 0, sizeof(M17_IPFrame));
	pkt->magic = htonl(M17_STREAM_PREFIX);
	pkt->streamid = htons(0xCCCC);
	init_lich(&pkt->lich, dst,src,frametype,nonce);
	pkt->framenumber = htons(framenumber);
	memcpy(pkt->payload, payload, 16);
	/*calc_crc(&pkt->crc, ""); //what bytes here?*/
}
/*void copy_lich_chunk(char * dest, M17_LICH * src, int chunkidx){*/
/*}*/
/*void copy_rflich_chunk(char * dest, M17_RFLICH * src, int chunkidx){*/
/*}*/
void init_rfframe(M17_IPFrame * pkt,
		M17_LICH * lich, //or RFLICH?
		uint16_t framenumber,
		char* payload
		){
	char *y = (char *) pkt;
	memset(y, 0, sizeof(M17_RFFrame));
	pkt->framenumber = htons(framenumber);
	/*copy_lich_chunk(pkt->lich, lich);*/

	memcpy(pkt->payload, payload, 16);
	/*calc_crc(&pkt->crc, ""); //what bytes here?*/
}
void m17_crc_lut_gen(uint16_t *crc_table, uint16_t poly)
{
	uint16_t remainder;

	for(uint16_t dividend=0; dividend<256; dividend++)
	{
		remainder=dividend<<8;

		for(uint8_t bit=8; bit>0; bit--)
		{
			if(remainder&(1<<15))
				remainder=(remainder<<1)^poly;
			else
				remainder=(remainder<<1);
		}

		crc_table[dividend]=remainder;
	}
}

uint16_t m17_calc_crc(const uint16_t* crc_table, const char* message, uint16_t nBytes)
{
	uint8_t data;
	uint16_t remainder=0xFFFF;

	for(uint16_t byte=0; byte<nBytes; byte++)
	{
		data=message[byte]^(remainder>>8);
		remainder=crc_table[data]^(remainder<<8);
	}

	return(remainder);
}
uint16_t m17_calc_crc_ez( char * data, size_t len ){
	uint16_t CRC_LUT[256];
	m17_crc_lut_gen( CRC_LUT , M17_CRC_POLY );
	uint16_t x = m17_calc_crc( CRC_LUT,  data, (uint16_t) len);
	return x;
}
void explain_frame(){
	//later: colorize output
	M17_IPFrame x;
	init_ipframe(&x, 
			0xCCCC, //streamid
			encode_callsign_base40("XLX307 D"),
			encode_callsign_base40("W2FBI"),
			5, //voice stream
			"AAAAAAAAAAAAAA", //mark out the nonce clearly
			13, //just as an example
			"BBBBBBBBBBBBBBBB" //mark the payload clearly
			);
	char *y = (char *) &x;
	printf("0x41 == nonce\n");
	printf("0x42 == payload\n");
	printf("0xCC == streamid\n");
	printf("fn is the frame number, where the high bit (leftmost) indicates last packet in the stream\n");
	printf("\n");
	printf("           \"M17 \"    SID     destination      source (continued next line)\n");
	printf("        ___________ _____ _________________ ___________\n");
	char * indent = "        ";
	for( int i = 0; i < (int)sizeof(M17_IPFrame); i++){
		if( i == 16 ){
			printf("\n\n%s_src_",indent);
			printf(" type_ _____0x41 == nonce_________________   ");
		}
		if( i == 32 ){
			printf("\n\n%s_nc__ _fn__ _____________payload_______________",indent);
			printf("  fn is the frame number");
		}
		if( i == 0x30 ){
			printf("\n\n%s_pay_______ CRC16",indent);
		}
		if( i>0 && i %16 == 0){ printf("\n"); }
		if(i%16==0){ printf("0x%04x  ",i); }
		printf("%02x ", y[i]);
		/*if( i == 49 ) printf("<- CRC16");*/
	}
}

typedef uint64_t (*callsign_func)(const char *callsign);
int callsign_test(const char * callsign, uint64_t expected ){
#define fns_len 2
	callsign_func fns[fns_len] = {
		m17_callsign2addr,
		encode_callsign_base40
	};
	char * fn_names[fns_len] = {
		"m17_callsign2addr",
		"encode_callsign_base40"
	};
	uint64_t results[fns_len];

	for( int i = 0; i < fns_len; i++){
		results[i] = (*fns[i])(callsign);
	}

	printf("Results: \n");
	int all_ok = 1;
	for( int i = 0; i < fns_len; i++){
		int ok = results[i] == expected;
		printf("\t%s\t0x%08lx\t%s\n", ok?"✔":"╳", results[i], fn_names[i] );
		if( !ok ){
			printf("\t\t0x%08lx expected\n", expected);
			all_ok = 0;
		}
	}
	return all_ok;
}
void callsign_tests(){
	int errors = 0;
	errors += !callsign_test("M17", 55533);
	errors += !callsign_test("W2FBI", 0x0161ae1f);
	errors += !callsign_test("XLX307 D", 0x00996A4193F8);
	printf("%d errors\n", errors);
}
#define assert(expr) ({expr?1:printf("Failure in assertion %s\n",#expr);})


//if want to run this directly, compile with -DMAIN=main
#ifndef MAIN
#define MAIN test_m17_c_main
#endif
int MAIN(int argc, char **argv){
	callsign_tests();

	assert(sizeof(M17_LICH) == LICH_sz);
	assert(sizeof(M17_IPFrame) == IPFrame_sz);

	assert(m17_calc_crc_ez("",0) ==  0xffff);
	assert(m17_calc_crc_ez("A",1) == 0x206E);
	assert(m17_calc_crc_ez("123456789",9) == 0x772B);

	explain_frame();

	return 0;
}

/*
 * output from git aa28914f1813be97878df0fecf1c0a1d59964187
0x41 == nonce
0x42 == payload
0xCC == streamid
fn is the frame number, where the high bit (leftmost) indicates last packet in the stream

           "M17 "    SID     destination      source (continued next line)
        ___________ _____ _________________ ___________
0x0000  4d 31 37 20 cc cc 00 99 6a 41 93 f8 00 00 01 61

        _src_ type_ _____0x41 == nonce_________________
0x0010  ae 1f 00 05 41 41 41 41 41 41 41 41 41 41 41 41

        __nonce____ _fn__ ______payload________________  fn is the frame number
0x0020  41 41 41 41 00 0d 42 42 42 42 42 42 42 42 42 42

        __more payload___ CRC16
0x0030  42 42 42 42 42 42 ff ff

*/
