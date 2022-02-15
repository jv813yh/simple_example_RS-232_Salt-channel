/**
 * ===============================================
 * client00.c   v.0.5
 * 
 * KEMT FEI TUKE, Diploma thesis
 *
 * CLIENT (creating / loading input file and 
 * salt handshake proccess and sending data
 * from client with Salt channelv2 cryptographic):
 *
 * Encryption:
 *      - Key exchange: X25519
 *      - Encryption: XSalsa20 stream cipher
 *      - Authentication: Poly1305 MAC
 *
 *  Signatures:
 *      - Ed25519
 *
 *  Hashing:
 *      - SHA512
 *
 * Deployment of Salt-Channelv2 cryptographic 
 * protocol on RS-232 communication channel.
 *
 *
 * Compileable on Windows with WinLibs standalone build of GCC 
 * and MinGW-w64 but also functional on Linux.
 * 
 *
 * Author-Jozef Vendel  Date- 24.12.2021 
 * ===============================================
 */


/* Basic libraries for working in C. */
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>

/* Salt-channel handshake proccess is measured between devices. */
#include <time.h>

/**
* Macro allows diagnostic information to be written 
* to the standard error file.
*/
#include <assert.h>

/* ===== RS-232 local macro definition & library ===== */

/* RS232 library */
#include "rs232.h"
/* /dev/ttyS0 (COM1 on windows) port */
#define CPORT_NR                0
/* 9600 baud, bit rate */
#define B_TRATE                 9600


/* ===== Salt-channel local macro definition & libraries ===== */

/**
* Salt-channel version 2 implementation. 
* Main source code of protocol.
*/
#include "salt.h"

/**
 * Function for dependency injection to make the salt-channel
 * available for reliable I/O channel. 
 * 
 * The I/O channel may be blockable or non-blockable.
 * 
 * If any error occurs the function must return SALT_ERROR and the error code
 * must be reported in p_channel->err_code. The function must only 
 * return SALT_SUCCESS when p_channel->size_expected == p_channel.size.
 * 
 * The read operation is always done in two steps:
 *  1. Read 4 size bytes, derive length n.
 *  2. Read the package of length n.
 *
 * The write opration is done in one step:
 *  1. Write { size[4] , package[n] }.
 */
#include "salt_io.h"

/**
 * Internal routines used by salt-channel as:
 * read / write  process state machine,
 * encrypts and wraps clear text data,
 * unwraps and decrypts a salt channel package,
 * auxiliary functions for reading 
 * and writing data (clear / encrypt / decrypt)
 * and others ....
 */
#include "salti_util.h"

/**
* Functions and macros for performing a salt-channel handshake.
*/
#include "salti_handshake.h"

/* ====== Public macro definitions ================ */

/** 
* Delay attack protection, 
* threshold for differense in milliseconds. 
*/
#define TRESHOLD                1000

//
#define PROTOCOL_BUFFER         128
/* Size, where the decrypted message starts in the buffer. */
#define ENC_MSG                 38
/* We need an input size of + 42 available for buffer */
#define BUFFER_AVAILABLE        42
/* Size of hash tag */
#define HASH_SIZE               64

/*======= Global function implementation ===========*/

/* Function for creating / loading input file */

uint8_t *loading_file(char *file, 
                      uint32_t *fileSize, 
                      int my_file);

/* Function for calculated hash from input data */

int crypto_hash(uint8_t *p_message, 
                uint8_t *p_calculated_hash, 
                int size);


int main(void) 
{	

/* ========  Variables & arrays ======== */

/**
 * Mode is a string in the form of "8N1", "7E2", etc.
 * 8N1 means eight databits, no parity, one stopbit. 
 * If in doubt, use 8N1.
 */
    char mode[]={'8','N','1',0},
         own_file[150];     /**< Own file name */

	int cport_nr = CPORT_NR,        
      	bdrate = B_TRATE,   

/**
 * If the salt handshake passes successfully, 
 * the verify is incremented and the data 
 * is exchanged -> while (verify){ ... }    
 */       
        verify = 0,

/**
 *  You can use a random file or a own file.
 */
        select_file = -1,

/*  Verify of calculated hash of data.  */
        verify_hash = 1;

/* The size of the transferred file. */    
 
    uint32_t file_size;
        

/** 
 * Buffer for storing data during 
 * the handshake process. 
 */
    uint8_t hndsk_buffer[SALT_HNDSHK_BUFFER_SIZE],  
/**
 * Buffer for initiates to add 
 * information about supported 
 * protocols to host. 
 */
            protocol_buffer[PROTOCOL_BUFFER],  
 /**
  * tx_buffer -> encrypted data
  * input -> loading input file 
  */     
            *tx_buffer, *input;                 

/* Time measurement variables */
    clock_t start_t, end_t;

/* Variables for working with salt-channel protocol */

	salt_channel_t pc_a_channel;   /**< Salt channel structure .*/

	salt_protocols_t protocols;    /**< Request information about protocols supported by host.
                                    *   The client may ask the host what protocols are supported 
                                    *   by using salt_a1a1. 
                                    */

    salt_ret_t ret, ret_msg;       /**< typedef enum, which can obtain values:
                                    *    SALT_SUCCESS,              
                                    *    SALT_PENDING,                   
                                    *    SALT_ERROR
                                    */

    salt_msg_t msg_out;    /**< Structure used for easier creating/reading/working with messages. */

    printf("\nA simple application that demonstrates the implementation of the Salt channel protocol\n");
    printf("on the RS232 communication channel and the sending of the loaded file.\n");

/* ========  Loading input data  ======== */
    
    printf("\n\n");
    printf("Do you want to use a random text file to test the application\n"); 
    printf("or use your own file?\nIf test file press 0, if own file press 1\n");
    scanf("%d", &select_file);
    printf("\n");

    if (select_file)
    {
        printf("Please enter name of your file with suffix, example: example.txt \n");
        printf("Make sure the file is in the current directory\n");
        scanf("%s", own_file);
    } else 
    {
        printf("You have decided to create a test file, follow the instructions.\n");
        printf("Please enter name of file with suffix, example: example.txt \n");
        scanf("%s", own_file);
    }
    printf("\n");

    /* Own file */
    if (select_file)
    /* Loading input data (your file)  */
        input = loading_file(own_file, &file_size, select_file);

    /* Random generate file and loading input data */
    else input = loading_file(own_file, &file_size, select_file); 


        printf("\nFile size is: %u\n", file_size);

        /* Allocated memory for data encryption */
        tx_buffer = (uint8_t *) malloc(file_size + BUFFER_AVAILABLE + HASH_SIZE);

        //Check if the memory has been successfully
        //allocated by malloc or not
        if (input == NULL || tx_buffer == NULL) 
        {
            printf("Memory not allocated in loading file\n");
            exit(0);
        }

/* ========  Calculated hash of data ======== */
     verify_hash = crypto_hash(input, &input[file_size], file_size);
     if(verify_hash != 0)
          printf("\nFailed to create hash\n");

     if(verify_hash == 0) 
          printf("\nA check tag has been created and attached to the data to verify integrity\n");
      printf("\n");
    

/* ========  Open port (COM number) on RS2_32  ======== */

    if(RS232_OpenComport(cport_nr, bdrate, mode, 0))
  	{
    	printf("Can not open comport\n");

    	return 0;
  	}

/* ========  Salt-channel version 2 implementation  ======== */

/**
 * Create a new Salt channel client 
 * 
 * @param p_channel     Pointer to channel handle.
 * @param mode          Salt channel mode { SALT_SERVER, SALT_CLIENT }
 * @param read_impl     User injected read implementation.
 * @param write_impl    Used injected write implementation.
 * @param time_impl     User injected get time implementation, may be NULL.
 *
 * @return SALT_SUCCESS The salt channel was successfully initiated.
 * @return SALT_ERROR   Any input pointer was a NULL pointer or invalid salt mode.
 * 
 */
    ret = salt_create(&pc_a_channel, SALT_CLIENT, my_write, my_read, &my_time);
    assert(ret == SALT_SUCCESS);

/* Initiates to add information about supported protocols to host. */
    ret = salt_protocols_init(&pc_a_channel, &protocols, protocol_buffer, sizeof(protocol_buffer));
    assert(ret == SALT_SUCCESS);

/* Add a protocol to supported protocols */
    ret = salt_protocols_append(&protocols, "ECHO", 4);
    assert(ret == SALT_SUCCESS);

/**
 * Creates and sets the signature used for the salt channel.
 *
 * @param p_channel Pointer to channel handle.
 *
 * @return SALT_SUCCESS The signature was successfully set.
 * @return SALT_ERROR   Any input pointer was a NULL pointer.
 */
    ret = salt_create_signature(&pc_a_channel); 
    assert(ret == SALT_SUCCESS);

/**
 * Initiates a new salt session.
 *
 * A new ephemeral key pair is generated and the read and write nonce
 * is reseted.
 *
 * @param p_channel         Pointer to channel handle.
 * @param hdshk_buffer      Pointer to buffer used for handsize. Must be at least
 *                          SALT_HNDSHK_BUFFER_SIZE bytes large.
 * @param hdshk_buffer_size Size of the handshake buffer.
 *
 * @return SALT_SUCCESS The session was successfully initiated.
 * @return SALT_ERROR   The channel handle or buffer was a NULL pointer.
 *
 */
    ret = salt_init_session(&pc_a_channel, hndsk_buffer, sizeof(hndsk_buffer));
    assert(ret == SALT_SUCCESS);

/**
 * Sets the context passed to the user injected read / write implementation.
 *
 * @param p_channel         Pointer to channel handle.
 * @param p_write_context   Pointer to write context.
 * @param p_read_context    Pointer to read context.
 *
 * @return SALT_SUCCESS The context was successfully set.
 * @return SALT_ERROR   p_channel was a NULL pointer.
 */
    ret = salt_set_context(&pc_a_channel, &cport_nr, &cport_nr);
    assert(ret == SALT_SUCCESS);

/* Set threshold for delay protection. */
    ret = salt_set_delay_threshold(&pc_a_channel, TRESHOLD);
    assert(ret == SALT_SUCCESS);


/* ========  Salt-handshake process  ======== */
    printf("\nCreating a Salt handshake:\n");

    int hnds = 1;
    while (hnds)
    {  
        hnds = 0;

/* Measurement salt handshake procces */

    	start_t = clock();
    	ret = salt_handshake(&pc_a_channel, NULL);
    	end_t = clock();
/**
 * @return SALT_SUCCESS When the handshake process is completed.
 * 
 * @return SALT_PENDING When the handshake process is still pending.
 * 
 * @return SALT_ERROR   If any error occured during the handshake process. 
 *                      At this time the session should be ended.
 */
    	if (ret == SALT_ERROR) 
    	{ 
	    	printf("Error during handshake:\r\n");
	        printf("Salt error: 0x%02x\r\n", pc_a_channel.err_code);
	        printf("Salt error read: 0x%02x\r\n", pc_a_channel.read_channel.err_code);
	        printf("Salt error write: 0x%02x\r\n", pc_a_channel.write_channel.err_code);
	        printf("Connection closed.\r\n");

        /* Closing application */
        	RS232_CloseComport(cport_nr);
	        assert(ret == SALT_ERROR);
    	} else if (ret == SALT_SUCCESS)
    	{
            /* If the salt handshake passed successfully, we can access the data exchange. */

    		printf("\nSalt handshake successful\r\n");
            printf("\t\n***** Salt channelv2 handshake lasted: %6.6f sec. *****\n", ((double) (end_t -
                   start_t) / (CLOCKS_PER_SEC))); 
            printf("\n");

            verify++;
    	}
    }

/* Sending data and waiting for a confirmation message. */
    while (verify)
    { 
    	ret_msg = SALT_ERROR;
        memset(tx_buffer, 0, file_size + BUFFER_AVAILABLE + HASH_SIZE);

/**
 * Write encrypted messages
 *
 * One or more messages can be sent using one encrypted message. Due to encryption
 * overhead the size of a single clear text message can not be larger than the
 * provided send: buffer - SALT_WRITE_OVERHEAD_SIZE (42) -> BUFFER_AVAILABLE !
 *
 * The content of p_buffer will be modified during the authenticated encryption.
 *
 * @param p_buffer  Pointer where to store received (clear text) data.
 * @param size      Size of clear text message to send.
 * @param p_msg     Pointer to message state structure.
 *
 * @return SALT_SUCCESS Message state structure was initialized.
 * @return SALT_ERROR   Bad buffer size or bad state of channel session.
 *
 */
        ret_msg = salt_write_begin(tx_buffer, file_size + BUFFER_AVAILABLE + HASH_SIZE, &msg_out);
        assert(ret_msg == SALT_SUCCESS);

/**
 * Copy a clear text message to be encrypted to next encrypted package.
 *
 * If this function is called more than once after salt_write_begin(),
 * all following clear text packages will be sent as one encrypted package. 
 * The content of p_buffer will be copied to the buffer of the p_msg structure,
 * because on the application layer it is possible to work with 
 * two types of packages Apppacket and Multipacket.
 *
 * The available buffer is in p_msg->buffer_available.
 * 
 * The function calls other support functions that verify whether the input data 
 * can be processed efficiently according to the rules of the salt channel protocol 
 * if no -> return SALT_ERROR.
 *
 * @param p_msg     Pointer to message state structure.
 * @param p_buffer  Pointer to clear text message.
 * @param size      Size of clear text message.
 *
 * @return SALT_SUCCESS A message was successfully appended to the state structure.
 * @return SALT_ERROR   The message was to large to fit in the state structure,
 *                      or does not meet the requirements
 *
 */

        ret_msg = salt_write_next(&msg_out, input, file_size + HASH_SIZE);
        assert(ret_msg == SALT_SUCCESS);

/**      
 * Encrypts and send the messages prepared in salt_write_begin and salt_write_next !
 *
 * The prepared message state structure will be encrypted and send to the other peer.
 * This routine will modify the data in the buffer of p_msg->p_buffer.
 *
 * The function calls other support functions that verify the correctness of the data 
 * readiness for encryption and also uses the salti_wrap() function for encryption, 
 * which, after verifying the success of the encryption, then sends the salti_io_write() 
 * function to the channel.
 *
 * @param p_channel     Pointer to salt channel handle.
 * @param p_msg         Pointer to message structure.
 *
 * @return SALT_SUCCESS A message was successfully sent.
 * @return SALT_ERROR   If any error occured during the sending process. 
 *                      If this occured, the session is considered
 *                      closed and a new handshake must be performed.
 *                      I.e., the session must be initated
 *                      and then a handshake.
 */

        ret_msg = salt_write_execute(&pc_a_channel, &msg_out, false);

/**
 * If the whole process has been successful and we sent the data to another side
 * we wait for a confirmation message, if it has not been successful we will end the program
 */
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
/**
 * Reads one or multiple encrypted message.
 *
 * The actual I/O operation of the read process.
 *
 * @param p_channel     Pointer to salt channel handle.
 * @param p_buffer      Pointer where to store received (clear text) data.
 * @param buffer_size   Size of p_buffer, must be greater or equal to SALT_READ_OVERHEAD_SIZE.
 * @param p_msg         Pointer to message structure to use when reading the message.
 *
 *
 * @return SALT_SUCCESS A message was successfully received.
 * @return SALT_ERROR   If any error occured during the read. If this occured, the session is considered
 *                      closed and a new handshake must be performed. I.e., the session must be initated
 *                      and then a handshake.
 */

            ret = salt_read_begin(&pc_a_channel, check_data, sizeof(check_data), &msg_in);
            assert(ret == SALT_SUCCESS);

/**
 *  Verification of the confirmation message. 
 *  The received report is compared, and when it is identical to the pattern of success, 
 *  the process is considered successful and ends proccess.
 */
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

/* ========  End of application  ======== */

    printf("\nClosing RS-232...\n");
    RS232_CloseComport(cport_nr);
    printf("Finished.\n");

//Free allocated memory
    free(tx_buffer);
    free(input);
    
    return 0;
}

/* Function for creating / loading file */

uint8_t *loading_file(char *file, 
                      uint32_t *fileSize, 
                      int my_file)
{   
    //Size of hash tag
    #define HASH_SIZE               64

    FILE *stream;
    uint8_t *input;
    uint32_t expected_size_file,
             range;

    /**
     * if my_file == 0 -> test file 
     * if my_file == 1 -> your file 
     * 
     * Creating our random test file
     * 
     */

    if(!my_file) 
    {
        if ((stream = fopen(file, "wb")) == NULL) 
        {
            printf("Failed to open create file %s\n", file);
            exit(0);
        }

        int i = 0;

        printf("Enter the approximate file size in bytes: \n");
        scanf("%u",&expected_size_file);
        expected_size_file = expected_size_file / 
                            (sizeof(expected_size_file) * sizeof(expected_size_file));
        printf("Enter max integer (range): \n");
        scanf("%u",&range);

        while(i++ < expected_size_file)
        {
            fprintf(stream, "Number %d. %u, ", i,  rand() % range);
        }

        fprintf(stream, "\nThis is the end of the file being tested :)");

        if(fclose(stream) == EOF) printf("Failed to closed file\n");

    }

    if ((stream = fopen(file, "rb")) == NULL) 
    {
        printf("Failed to open file %s\n", file);
        exit(0);
    }

    fseek(stream, 0L, SEEK_END);
    *fileSize = ftell(stream);
    fseek(stream, 0L, SEEK_SET);

    input = (uint8_t *) malloc(*fileSize + HASH_SIZE);
    if (input == NULL) 
    {
        printf("Memory not allocated.\n");
        exit(0);
    }

    fread(input, 1, *fileSize, stream);


    if(fclose(stream) == EOF) printf("Failed to closed file\n");

    return input;

}

int crypto_hash(uint8_t *p_message, 
                uint8_t *p_calculated_hash, 
                int size)
{

    int ret;
    ret = api_crypto_hash_sha512(p_calculated_hash, p_message, size);
   
   return ret;
}
