/**
 * ===============================================
 * server00.c     v.1.1
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
 *
 * Compileable on Windows with WinLibs standalone build of GCC 
 * and MinGW-w64 but also functional on Linux.
 *
 * Author-Jozef Vendel  Date- 24.12.2021 
 * ===============================================
 */

/* Basic libraries for working in C. */
#include <stdio.h>
#include <stdint.h>

/* Transmission proccess is measured between devices. */
#include <time.h>

/**
* Macro allows diagnostic information to be written 
* to the standard error file.
*/
#include <assert.h>

/* ===== RS-232 local macro definition & libraries ===== */
/* RS232 library */
#include "rs232.h"
/* Created functions for work with protocol on RS-232 */
#include "salt_example_rs232.h"
/* /dev/ttyS0 (COM1 on windows) port */
#define CPORT_NR                1
/* 115200 baud, bit rate */
#define B_TRATE                 115200

/* ===== Salt-channel libraries ===== */
#include "salt.h"
#include "salt_io.h"

/* Ready server_sk_key */
#include "server_sk_key.h"

int main(void) 
{ 
/* ========  Variables & arrays ======== */
    int cport_nr = CPORT_NR,        
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

    /*
     * expected_size:   expected file size
     * block_size:      expected size of block
     * decrypt_size:    number of decrypted data
     * check_read:      return check value
     */
    uint32_t expected_size = 0, block_size = 0,
        decrypt_size = 0, check_read;

    /* Time measurement variables */
    clock_t start_t, end_t;

/* ======= Variables for working with salt-channel protocol =========== */

    salt_channel_t pc_b_channel;
    salt_protocols_t protocols;
    salt_msg_t msg_in;
    salt_ret_t ret_msg, ret_hndshk;

/* ======== Program information ======== */
    printf("\nA simple application that demonstrates the implementation of the Salt channel protocol\n");
    printf("on the RS232 communication channel and the receiving of the file in blocks and store them in the file.\n");

/* ========  Open port (COM number) on RS2_32  ======== */

    if(RS232_OpenComport(cport_nr, bdrate, mode, 0))
    {
        printf("Can not open comport\n");

        return 0;
    }

/* ========  Salt-channel version 2 implementation and Salt handshake ======== */
    printf("\n");
    ret_hndshk = salt_impl_and_hndshk_server(&pc_b_channel,
                                             &protocols,
                                             my_write,
                                             my_read,
                                             &cport_nr,
                                             &my_time,
                                             host_sk_sec,
                                             TRESHOLD);
    if (ret_hndshk == SALT_SUCCESS) verify++;
    else 
    {
        printf("Salt Handshake failed\n");
        return -1;
    }

/* ======== Receiving data and sending confirmation message ======== */
    while (verify)
    {   
        /* Variables for receiving and decrypting data of expected sizes */
        uint8_t expected_size_buffer[STATIC_ARRAY];
        salt_msg_t out_expected_size;
        ret_msg = SALT_ERROR;

        int32_t check_size_value = salt_read_small_messages(&pc_b_channel,
                                                            expected_size_buffer,
                                                            STATIC_ARRAY,
                                                            &out_expected_size,
                                                            &expected_size,
                                                            1);
        if (check_size_value == 1)
        {
            printf("\nThe expected size of the transferred data has been received\n\n");
            assert(check_size_value == 1);
        }
        else
        {
            printf("\nThe expected file size could not be accepted\n");
            assert(check_size_value == 1);
        } 

        check_size_value = 0;
        check_size_value = salt_read_small_messages(&pc_b_channel,
                                                    expected_size_buffer,
                                                    STATIC_ARRAY,
                                                    &out_expected_size,
                                                    &block_size,
                                                    1);
        if (check_size_value == 1)
        {
            printf("\nThe expected size of the block data has been received\n\n");
            assert(check_size_value == 1);
        }
        else
        {
            printf("\nThe expected block size could not be accepted\n");
            assert(check_size_value == 1);
        } 

        /* Opens the file received_data.txt */
        FILE *fp;
        fp = fopen("received_data.txt", "wb");

        if(fp == NULL)
        {
            printf("Error opening file\n");
            exit(1);
        }

        /* Reads encrypted data in blocks */
        uint8_t rx_buffer[block_size + SALT_READ_OVRHD_SIZE],
                copy_buffer[block_size];
        
        decrypt_size = 0;

        /* Start of transmission measurement */
        start_t = clock();
        do
        { 
            check_read = salt_read_and_decrypt_server(&pc_b_channel,
                                                      rx_buffer,
                                                      block_size + SALT_READ_OVRHD_SIZE,
                                                      &msg_in,
                                                      copy_buffer,
                                                      &decrypt_size,
                                                      fp);
            if (check_read == 1) ret_msg = SALT_SUCCESS;
            else
            {   
                printf("Failed to process received data\n");
                assert(check_read == 1);
            } 

        } while(decrypt_size < expected_size);
        /* End of data transmission measurement */ 
        end_t = clock();

        /* Closed file */
        fclose(fp);

        /* Sending message about the proccess -> SUCCESS or FAIL */
        uint8_t check_data[STATIC_ARRAY];
        uint32_t check_return_confirm, length_check;
        printf("\n\nConclusion:");

        /* If the data has been successfully received and decrypted */      
        if (ret_msg == SALT_SUCCESS)
        {
            strcpy((char *)check_data, "Sending of data was successful :)\n");
            printf("\n%s\n", check_data);
            length_check = strlen((const char*)check_data);

            check_return_confirm = salt_write_small_messages(&pc_b_channel,
                                                            check_data,
                                                            length_check,
                                                            STATIC_ARRAY);
            if (check_return_confirm != 1)
            {   
                printf("Failed to send confirmation message\n");
                assert(check_return_confirm == 1);
            } 
            /* We can end the process of receiving data */
            break;
        } else 
        /* If the data has been unsuccessfully received and decrypted */
        {
            strcpy((char *)check_data, "Sending of data was not successful :)\n");
            printf("\n%sYou must send it again :/\n", check_data);
            length_check = strlen((const char *)check_data);

            check_return_confirm = salt_write_small_messages(&pc_b_channel,
                                                            check_data,
                                                            length_check,
                                                            STATIC_ARRAY);
            if (check_return_confirm != 1)
            {   
                printf("Failed to send confirmation message\n");
                assert(check_return_confirm == 1);
            } 
            /* We can not end the process of receiving data and WE must send it again */
        }
    } /* End of receiving data and sending confirmation message */

/* ======================  End of application  ===================== */

    double elapsed = (double)(end_t - start_t)  / CLOCKS_PER_SEC;
    printf("\n****************** Summary *********************\n");
    printf("File transfer about size: %u time took seconds: %0.f\n\n", expected_size, elapsed);

    printf("\nClosing RS-232...\n");
    RS232_CloseComport(cport_nr);
    printf("Finished.\n");

    return 0;
}

