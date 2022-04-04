/**
 * ===============================================
 * client00.c   v.1.2
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
#include <stdint.h>
#include <stdlib.h>

/* Transmission proccess is measured between devices. */
#include <time.h>

/**
* Macro allows diagnostic information to be written 
* to the standard error file.
*/
#include <assert.h>

/* ===== RS-232 local macro definition & library ===== */
/* RS232 library */
#include "rs232.h"
/* Created functions for work */
#include "salt_example_rs232.h" 
/* /dev/ttyS0 (COM1 on windows) port */
#define CPORT_NR                0
/* 115200 baud, bit rate */
#define B_TRATE                 115200

/* ===== Salt-channel local macro definition & libraries ===== */
#include "salt.h"
#include "salt_io.h"

#ifdef _WIN32
#include <Windows.h>
#else
#include <unistd.h>
#endif

/* ====== Public macro definitions ================ */
/* The max size of one data in one block sent */
#define BLOCK_SIZE             4067
/* Sleep milliSeconds  */
#define MILISECONDS            100

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
        select_file = -1;

    /* The size of the transferred file. */    
 
    uint32_t file_size, 

    /*  Test return value for sleep()  */
        sleep_return,
    /* Test return value for sending data */
        verify_send_data;

    /**
    * tx_buffer -> encrypted data
    * input -> loading input file 
    */     
    uint8_t  *tx_buffer, *input;               

    /* Time measurement variables */
    clock_t start_t, end_t;

/* ======= Variables for working with salt-channel protocol ======== */

	salt_channel_t pc_a_channel;   /**< Salt channel structure .*/

    /*
     * typedef enum, which can obtain values:
     * SALT_SUCCESS, SALT_PENDING, SALT_ERROR                                
     */
    salt_ret_t ret_msg, ret_hndsk;  

    salt_msg_t msg_out;    /**< Structure used for easier creating/reading/working with messages. */

/* ======== Program information ======== */
    printf("\nA simple application that demonstrates the implementation of the Salt channel protocol\n");
    printf("on the RS232 communication channel and the sending of the loaded file.\n");

/* ========  Creating / loading input data  ======== */
    printf("\n\n");
    printf("Do you want to use a random text file to test the application\n"); 
    printf("or use your own file?\nIf test file press 0, if own file press 1\n");
    if (EOF == scanf("%d", &select_file))
    {
        printf("Bad choice for file only 0 or 1 :(\n");
        return -1;
    }
    printf("\n");
    if (select_file)
    {
        printf("Please enter name of your file with suffix, example: example.txt \n");
        printf("Make sure the file is in the current directory\n");
        if (EOF == scanf("%s", own_file))
        {
            printf("Bad choice for file only 0 or 1 :(\n");
            return -1;
        }
    } else 
    {
        printf("You have decided to create a test file, follow the instructions.\n");
        printf("Please enter name of file with suffix, example: example.txt \n");
        if (EOF == scanf("%s", own_file))
        {
            printf("Bad name for your file :(\n");
            return -1;
        }
    }
    printf("\n");

    /* Loading input data (your file)  */
    if (select_file) input = loading_file(own_file, 
                                          &file_size, 
                                          select_file);

    /* Random generate file and loading input data */
    else input = loading_file(own_file, 
                              &file_size, 
                              select_file);

    printf("\nFile size is: %u\n", file_size);
    /* 
     * Calculating the number of blocks and the additional memory 
     * required to work with the data for protocol
     */
    uint32_t count_of_write_blocks = calculated_count_of_blocks(file_size,
                                                                BLOCK_SIZE,
                                                                SALT_WRITE_OVRHD_SIZE);
    count_of_write_blocks = SALT_WRITE_OVRHD_SIZE + (count_of_write_blocks * 2);
    if (count_of_write_blocks <= 0)
    {
        printf("Error calculating memory size for blocks\n");
        return -1;
    }
    /* Allocates the requested memory and returns a pointer to it */
    tx_buffer = (uint8_t *) malloc(file_size + count_of_write_blocks);
    //Check if the memory has been successfully
    //allocated by malloc or not
    if(tx_buffer == NULL)
    {
        printf("Memory not allocated.\n");
        exit(0);   
    }
    printf("\n");
    
/* ===========  Open port on RS2_32  ============ */

    if(RS232_OpenComport(cport_nr, bdrate, mode, 0))
  	{
    	printf("Can not open comport\n");
    	return 0;
  	}

/* ========  Salt-channel version 2 implementation and Salt handshake ======== */
    ret_hndsk = salt_impl_and_hndshk(&pc_a_channel, 
                                    my_write,
                                    my_read,
                                    &cport_nr,
                                    &my_time,
                                    TRESHOLD);
    if (ret_hndsk == SALT_SUCCESS) verify++;
    else 
    {
        printf("Salt Handshake failed\n");
        return -1;
    }
    if ((sleep_return = sleep_miliseconds_win_linux(MILISECONDS * 20)) == 0)
    {
        printf("Problem during sleep I/O");
        return SALT_ERROR;
    }

/* ========== Sending data and waiting for a confirmation message =========== */
    while (verify)
    {   
        int32_t size_check = salt_convert_size_and_send(&pc_a_channel, file_size);
        if (size_check != 1) printf("Failed to send size message");

        if ((sleep_return = sleep_miliseconds_win_linux(MILISECONDS * 20)) == 0)
        {
            printf("Problem during sleep I/O");
            return -1;
        }

        size_check = salt_convert_size_and_send(&pc_a_channel, BLOCK_SIZE);
        if (size_check != 1) printf("Failed to send size message");

        if ((sleep_return = sleep_miliseconds_win_linux(MILISECONDS * 20)) == 0)
        {
            printf("Problem during sleep I/O");
            return -1;
        }
       
        /* Start of transmission measurement */
        start_t = clock();
        verify_send_data = salt_encrypt_and_send(&pc_a_channel,
                                                tx_buffer,
                                                file_size + count_of_write_blocks,
                                                file_size,
                                                BLOCK_SIZE,
                                                input,
                                                &msg_out);
        /* End of data transmission measurement */ 
        end_t = clock();
        if (verify_send_data == 1) ret_msg = SALT_SUCCESS;
        else ret_msg = SALT_ERROR;

        /**
         * If the whole process has been successful and we sent the data to another side
         * we wait for a confirmation message, if it has not been successful we will end the program
         */
        if(ret_msg == SALT_ERROR) 
        {
            printf("Error during writing:\r\n");
            printf("Salt error read: 0x%02x\r\n", pc_a_channel.write_channel.err_code);
            RS232_CloseComport(cport_nr);
            assert(ret_msg == SALT_ERROR);
        } else if (ret_msg == SALT_SUCCESS)
        {
            uint8_t check_data[STATIC_ARRAY];
            memset(check_data, 0, STATIC_ARRAY);

            salt_msg_t msg_in;
            printf("\n");

            uint32_t received_verify = salt_read_small_messages(&pc_a_channel,
                                                                check_data,
                                                                sizeof(check_data),
                                                                &msg_in,
                                                                NULL,
                                                                0);
            if (received_verify != 1) 
            {
                printf("Failed to read confirmation transmission transfer message\n");
                assert(received_verify == 1);
            }
            /**
             *  Verification of the confirmation message. 
             *  The received report is compared, and when it is identical to the pattern of success, 
             *  the process is considered successful and ends proccess.
             */
            int result = memcmp(&check_data[SALT_READ_OVRHD_SIZE], "Sending of data was successful :)\n",
            strlen("Sending of data was successful :)\n"));
            if (result == 0) break;
            else 
            {
                fprintf(stdout, "Sending of data was not successful :/\n");
                fprintf(stdout, "I must send it again\n");
            }
        } /* End of send of data in block */
	} /* End of sending data and confirm them  while(verify){...} */

/* ===================  End of application  ======================== */

    double elapsed = (double)(end_t - start_t)  / CLOCKS_PER_SEC;
    printf("\n****************** Summary *********************\n");
    printf("File transfer about size: %u time took seconds: %0.f\n\n", file_size, elapsed);

    printf("\nClosing RS-232...\n");
    RS232_CloseComport(cport_nr);
    printf("Finished.\n");

    //Free allocated memory
    free(tx_buffer);
    free(input);
    
    return 0;
}



