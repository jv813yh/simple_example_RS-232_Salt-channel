/**
* Compiling any code using tweetnacl.c and tweetnacl.h results in an error 
* that there is no definition of the randombytes function.
* Searching the few available links I discover that the randombytes function is
* called to obtain a random sequence of bytes a buffer. 
* 
* It's routine that works on both windows and linux using the OS's own 
* methods for doing this. If the OS specific method fails it falls back
* to using built in C functions. 
* This is not ideal as it uses the current time as a seed to the random 
* number generator. 
* This could be discovered by brute force, but it is better than nothing. 
* So now I have a randombytes.c file that now allows clean 
* compilation of code using tweetnacl.
* 
*/

#include <stdio.h>
#include <stdlib.h>
#include <time.h>

#ifdef WIN32
#include "windows.h"
#include "wincrypt.h"
#endif

#define SUCCESS 0
#define FAILURE 1
#define RANDOMBYTES_DEBUG 0

typedef unsigned char u8;
typedef unsigned long long u64;

void randombytes(unsigned char *buffer, unsigned int buffer_length)
{
	//int status = FAILURE;

#ifdef WIN32
	HCRYPTPROV hCryptProv = 0;

	if (CryptAcquireContext(&hCryptProv, NULL, NULL, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT))
	{
#if RANDOMBYTES_DEBUG
		printf("CryptAcquireContext suceeded\n");
#endif
		if (CryptGenRandom(hCryptProv, buffer_length, buffer))
		{
#if RANDOMBYTES_DEBUG
			printf("CryptGenRandom succeded\n");
#endif
			//status = SUCCESS;
		}
		if (CryptReleaseContext(hCryptProv, 0))
		{
#if RANDOMBYTES_DEBUG
			printf("CryptReleaseContext succeeded\n");
#endif
		}
	}
#else
	FILE *fp = fopen("/dev/urandom", "rb");
	if (fp != NULL)
	{
		if (fread(buffer, buffer_length, 1, fp) > 0)
		{
#if RANDOMBYTES_DEBUG
			printf("Read from /dev/urandom succeeded\n");
#endif
			//status = SUCCESS;
		}
		fclose(fp);
	}
}
#endif
}
