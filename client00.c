/*
 * client00.c   v.0.3
 * 
 * KEMT FEI TUKE, Diploma thesis
 *
 * CLIENT (Salt handshake and sending data
 * from client with Salt channelv2 cryptographic)
 *
 * Deployment of Salt-Channelv2 cryptographic network protocol on RS-232
 * communication channel.
 * 
 * Windows/Linux 
 *
 * Author-Jozef Vendel  Date- 24.12.2021 
 * ===============================================
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include <assert.h>
#include <time.h>

//RS232 library
#include "rs232.h"

//Libraries of Salt channelv2
#include "salt.h"
#include "salt_io.h"
#include "salti_util.h"
#include "salti_handshake.h"

//Maximum size of data that the program can process
#define MAX_SIZE                UINT32_MAX   
//Delay attack protection, threshold for differense in milliseconds
#define TRESHOLD 				1000
//
#define PROTOCOL_BUFFER 		128
//Size, where the decrypted message starts in the buffer 
#define ENC_MSG             38

int main(int argc, char *argv[]) 
{	
	int cport_nr = 2,        /* /dev/ttyS0 (COM1 on windows) */
      	bdrate = 9600,       /* 9600 baud */
      	fileSize, verify = 0;

    uint8_t hndsk_buffer[SALT_HNDSHK_BUFFER_SIZE], 
            protocol_buffer[PROTOCOL_BUFFER],
            *tx_buffer, *input;

    clock_t start_t, end_t;

  	char mode[]={'8','N','1',0};

//Variables for working with salt channel protocol
	salt_channel_t pc_a_channel;
	salt_protocols_t protocols;
    salt_ret_t ret, ret_msg;
    salt_msg_t msg_out;

//Loading input data
    FILE *stream;
  	if ((stream = fopen(argv[1], "rb")) == NULL) 
  	{
    	printf("Failed to open file\n");
    	return 1;
 	}

 	fseek(stream, 0L, SEEK_END);
 	fileSize = ftell(stream);
 	fseek(stream, 0L, SEEK_SET);

 	input = (uint8_t *) malloc(fileSize);
    tx_buffer = (uint8_t *) malloc(fileSize);

//Check if the memory has been successfully
//allocated by malloc or not
  if (input == NULL || tx_buffer == NULL) {
      printf("Memory not allocated.\n");
      exit(0);
  }

  	fread(input, 1, fileSize, stream);
    printf("File size is: %u\n", fileSize);

  	if(fclose(stream) == EOF) printf("Failed to closed file\n");

//Open port (COM number) on RS2_32
    if(RS232_OpenComport(cport_nr, bdrate, mode, 0))
  	{
    	printf("Can not open comport\n");

    	return 0;
  	}

//Create Salt channel client
    ret = salt_create(&pc_a_channel, SALT_CLIENT, my_write, my_read, &my_time);
    assert(ret == SALT_SUCCESS);

//Initiates to add information about supported protocols 
    ret = salt_protocols_init(&pc_a_channel, &protocols, protocol_buffer, sizeof(protocol_buffer));
    assert(ret == SALT_SUCCESS);

//Add a protocol to supported protocols
    ret = salt_protocols_append(&protocols, "ECHO", 4);
    assert(ret == SALT_SUCCESS);

//Creating pairs of signature keys
    ret = salt_create_signature(&pc_a_channel); 
    assert(ret == SALT_SUCCESS);

//Setting up other necessary cryptographic operations to use the protocol properly
    ret = salt_init_session(&pc_a_channel, hndsk_buffer, sizeof(hndsk_buffer));
    assert(ret == SALT_SUCCESS);

//Setting up socket with function for read messages and write messages
    ret = salt_set_context(&pc_a_channel, &cport_nr, &cport_nr);
    assert(ret == SALT_SUCCESS);

//Setting up delay treshold
    ret = salt_set_delay_threshold(&pc_a_channel, TRESHOLD);
    assert(ret == SALT_SUCCESS);

    printf("\nA simple application that demonstrates the implementation of the Salt channel protocol\n");
    printf("on the RS232 communication channel and the sending of the loaded file.\n");
    printf("\nCreating a Salt handshake:\n");

//Salt handshake procces
    int hnds = 1;
    while (hnds)
    {  
        hnds = 0;

//Measurement salt handshake procces
    	start_t = clock();
    	ret = salt_handshake(&pc_a_channel, NULL);
    	end_t = clock();

//If the salt handshake failed, the rs232 interface closes 
//and the program is exits with assert()
    	if (ret == SALT_ERROR) 
    	{ 
	    	printf("Error during handshake:\r\n");
	        printf("Salt error: 0x%02x\r\n", pc_a_channel.err_code);
	        printf("Salt error read: 0x%02x\r\n", pc_a_channel.read_channel.err_code);
	        printf("Salt error write: 0x%02x\r\n", pc_a_channel.write_channel.err_code);
	       
	        printf("Connection closed.\r\n");
        	RS232_CloseComport(cport_nr);
	        assert(ret == SALT_ERROR);
    	} else if (ret == SALT_SUCCESS)
//If the salt handshake passed successfully, we can access the data exchange
    	{
    		printf("\nSalt handshake successful\r\n");
            printf("\t\n***** Salt channelv2 handshake lasted: %6.6f sec. *****\n", ((double) (end_t -
                   start_t) / (CLOCKS_PER_SEC))); 
            printf("\n");
            verify = 1;
    	}
    }

//Sending data and waiting for a confirmation message
    while (verify)
    { 
    	ret_msg = SALT_ERROR;
        memset(tx_buffer, 0, fileSize);
        //input[fileSize] = '\0';

//Prepare the message before encrypting and sending 
        ret_msg = salt_write_begin(tx_buffer, MAX_SIZE, &msg_out);
        assert(ret_msg == SALT_SUCCESS);

//Copy clear text message to be encrypted to next encrypted package
        ret_msg = salt_write_next(&msg_out, input, fileSize);
        assert(ret_msg == SALT_SUCCESS);

//Wrapping and creating encrypted messages, sending for server 
        ret_msg = salt_write_execute(&pc_a_channel, &msg_out, false);

//If the whole process has been successful and we sent the data to another side
//we wait for a confirmation message, if it has not been successful we will end the program
        if(ret_msg == SALT_ERROR) {
            printf("Failed to encrypt or send message from server\n");
            RS232_CloseComport(cport_nr);
            assert(ret_msg == SALT_ERROR);
        } else if (ret_msg == SALT_SUCCESS)
        {
            uint8_t check_data[1024];
            memset(check_data, 0, sizeof(check_data));
            salt_msg_t msg_in;
            salt_ret_t ret = SALT_ERROR;
            printf("\n");

//Received encryption data, decryption them
            ret = salt_read_begin(&pc_a_channel, check_data, sizeof(check_data), &msg_in);
            assert(ret == SALT_SUCCESS);

//Verification of the confirmation message
            int result = memcmp(&check_data[ENC_MSG], "Sending of data was successful :)\n",
            strlen("Sending of data was successful :)\n"));
            if (result == 0) break;
            else 
            {
                fprintf(stdout, "Sending of data was not successful :/\n");
                fprintf(stdout, "I must send it again\n");
            }
        }
	}

    printf("\nClosing RS-232...\n");
    RS232_CloseComport(cport_nr);
    printf("Finished.\n");

    free(tx_buffer);
    free(input);
    return 0;
}


