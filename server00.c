/**
 * ===============================================
 * server00.c     v.0.6
 *
 * KEMT FEI TUKE, Diploma thesis
 *
 * SERVER (Salt handshake proccess and receivind data
 * from client (client00.c) with Salt channelv2 cryptographic):
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
 * Deployment of Salt-Channelv2 cryptographic protocol 
 * on RS-232 communication channel.
 *
 * In the client00.c are briefly describes header files, 
 * macros, values, proccesses, functions ...
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
#define CPORT_NR                1
/* 9600 baud, bit rate */
#define B_TRATE                 9600

/* ===== Salt-channel local macro definition & libraries ===== */
/* In the client00.c are briefly describes this header files */
#include "salt.h"
#include "salt_io.h"
#include "salti_util.h"
#include "salti_handshake.h"

/* Ready server_sk_key */
#include "server_sk_key.h"

/* ====== Public macro definitions ================ */

/* Maximum size of data that the program can process */
#define MAX_SIZE                UINT32_MAX   

/** 
* Delay attack protection, 
* threshold for differense in milliseconds. 
*/
#define TRESHOLD                20000
//
#define PROTOCOL_BUFFER         128

int main(void) 
{ 

/* ========  Variables & arrays ======== */

    int cport_nr = CPORT_NR ,        
        bdrate = B_TRATE,

/**
 * If the salt handshake passes successfully, 
 * the verify is incremented and the data 
 * is received -> while (verify){ ... }    
 */       
        verify = 0;    
/**
 * Mode is a string in the form of "8N1", "7E2", etc.
 * 8N1 means eight databits, no parity, one stopbit. 
 * If in doubt, use 8N1.
 */  
    char mode[]={'8','N','1',0};

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
 * rx_buffer -> receiving and decrypted data
 */   
            *rx_buffer;

/*  Space allocation */
    rx_buffer = (uint8_t *) malloc(MAX_SIZE);

    //Check if the memory has been successfully
    //allocated by malloc or not
    if (rx_buffer == NULL)
    {
      printf("Memory not allocated.\n");
      exit(0);
    }

/* Variables for working with salt-channel protocol */
/* In the client00.c are briefly describes this variables */

    salt_channel_t pc_b_channel;
    salt_protocols_t protocols;
    salt_msg_t msg_in;
    salt_ret_t ret_msg, ret;

/* Time measurement variables */
    clock_t start_t, end_t;


/* ========  Open port (COM number) on RS2_32  ======== */

    if(RS232_OpenComport(cport_nr, bdrate, mode, 0))
    {
        printf("Can not open comport\n");

        return 0;
    }

/* ========  Salt-channel version 2 implementation  ======== */
/* In the client00.c are briefly describes this fuctions */

//Creates a new salt channel
    ret = salt_create(&pc_b_channel, SALT_SERVER, my_write, my_read, &my_time);
    assert(ret == SALT_SUCCESS);

//Initiates to add information about supported protocols 
    ret = salt_protocols_init(&pc_b_channel, &protocols, protocol_buffer, sizeof(protocol_buffer));
    assert(ret == SALT_SUCCESS);

//Add a protocol to supported protocols
    ret = salt_protocols_append(&protocols, "ECHO", 4);
    assert(ret == SALT_SUCCESS);

//Sets the signature used for the salt channel
    ret = salt_set_signature(&pc_b_channel, host_sk_sec);
    assert(ret == SALT_SUCCESS);

//New ephemeral key pair is generated and the read and write nonce  is reseted
    ret = salt_init_session(&pc_b_channel, hndsk_buffer, sizeof(hndsk_buffer));
    assert(ret == SALT_SUCCESS);

//Sets the context passed to the user injected read implementation
    ret = salt_set_context(&pc_b_channel, &cport_nr, &cport_nr);
    assert(ret == SALT_SUCCESS);

//Set threshold for delay protection
    ret = salt_set_delay_threshold(&pc_b_channel, TRESHOLD);
    assert(ret == SALT_SUCCESS);

    printf("\nA simple application that demonstrates the implementation of the Salt channel protocol\n");
    printf("on the RS232 communication channel and the reciving file and display it on the screen.\n");
    printf("\nCreating a Salt handshake:\n");

/**
 * Salt handshake procces and functions about messages are briefly 
 * commented in client00.c
 */

//Measurement salt handshake procces
    start_t = clock();
    ret = salt_handshake(&pc_b_channel, NULL);
    end_t = clock();

//If the salt handshake failed, the rs232 interface closes 
//and the program is exits with assert()
    if (ret == SALT_ERROR)  
    {
        printf("Error during handshake:\r\n");
        printf("Salt error: 0x%02x\r\n", pc_b_channel.err_code);
        printf("Salt error read: 0x%02x\r\n", pc_b_channel.err_code);
        printf("Salt error write: 0x%02x\r\n", pc_b_channel.write_channel.err_code);
        
        printf("Connection closed.\r\n");
        RS232_CloseComport(cport_nr);
        assert (ret == SALT_ERROR);
    }
//If the salt handshake passed successfully, we can access the data exchange
    if (ret == SALT_SUCCESS) 
    {
        printf("\nSalt handshake successful\r\n");
        printf("\n");
        printf("\t\n***** Salt channelv2 handshake lasted: %6.6f sec. *****\n", ((double) (end_t -
        start_t) / (CLOCKS_PER_SEC))); 
        verify = 1;
        printf("\n");
    }
//Receiving data and sending confirmation message
    while (verify)
    {
        ret_msg = SALT_ERROR;
        memset(rx_buffer, 0, MAX_SIZE);

//Reads encrypted message
        ret_msg = salt_read_begin(&pc_b_channel, rx_buffer, MAX_SIZE, &msg_in);

//If the data has been successfully received and decrypted       
        if (ret_msg == SALT_SUCCESS)
        {
            uint8_t tx_buffer[1024], check_data[1024];
            salt_msg_t out_msg;
            strcpy((char *)check_data, "Sending of data was successful :)\n");
            printf("\n\nConclusion:");
            printf("\n%s\n", check_data);
            int length_check = strlen((const char*)check_data);

//Prepare the message before encrypting and sending 
            ret = salt_write_begin(tx_buffer, sizeof(tx_buffer), &out_msg);
            assert(ret == SALT_SUCCESS);

//Copy clear text message to be encrypted to next encrypted package
            ret = salt_write_next(&out_msg, check_data, length_check);
            assert(ret == SALT_SUCCESS);

//Wrapping and creating encrypted messages, sending for client 
            ret = salt_write_execute(&pc_b_channel, &out_msg, false);
            assert(ret == SALT_SUCCESS);
            break;
        } else 
//If the data has been unsuccessfully received and decrypted  
        {
            uint8_t tx_buffer[1024], check_data[1024];
            salt_msg_t out_msg;
            strcpy((char *)check_data, "Sending of data was not successful :)\n");
            printf("\n%syou must send it again :/\n", check_data);
            int length_check = strlen((const char *)check_data);

            ret = salt_write_begin(tx_buffer, sizeof(tx_buffer), &out_msg);
            assert(ret == SALT_SUCCESS);
            ret = salt_write_next(&out_msg, check_data, length_check);
            assert(ret == SALT_SUCCESS);
            ret = salt_write_execute(&pc_b_channel, &out_msg, false);
            assert(ret == SALT_SUCCESS);
        }
    }

/* ========  End of application  ======== */
    
//Free allocated memory
    free(rx_buffer);

    printf("\nClosing RS-232...\n");
    RS232_CloseComport(cport_nr);
    printf("Finished.\n");

    return 0;
}

