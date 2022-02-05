/*
 * salt_io.c    v.0.4
 *
 * Input, Output, Timestamp
 *
 * Functions needed for sending/receiving messages, creating time stamps 
 * in the Salt channelv2 protocol on RS-232 interface
 *
 * Windows/Linux  
 *
 * Author-Jozef Vendel  Date- 28.12.2021 
 * KEMT FEI TUKE, Diploma thesis
 * ===============================================
 */

#include <unistd.h>
#include <stdio.h>
#include <inttypes.h>
#include <math.h>
#include <stdio.h>
#include <sys/time.h>
#include <string.h>

//Library of Salt channelv2
#include "salti_util.h"
#include "salt_io.h"

//RS232 library
#include "rs232.h"


static salt_ret_t get_time(salt_time_t *p_time, uint32_t *time);

salt_time_t my_time = {
    get_time,
    NULL
};

//Function for sending messages
salt_ret_t my_write(salt_io_channel_t *p_wchannel)
{
    int cport_nr = *((int *) p_wchannel->p_context);
    int bytes_sent = 0; 
    
//Sending messages through cport_nr
    int begin = 0;
    while (begin < p_wchannel->size_expected) { 
        bytes_sent = RS232_SendBuf(cport_nr, p_wchannel->p_data + begin, p_wchannel->size_expected - begin);
        if (bytes_sent != 0)
            printf("Sent %d bytes.\n", bytes_sent);

//Addition size of bytes
        begin += bytes_sent;  
        p_wchannel->size += bytes_sent;

#ifdef _WIN32
    Sleep(1000);
#else
    usleep(1000000);  /* sleep for 1 Second */
#endif
    }

    return SALT_SUCCESS; 
}

//Function for receiving messages
salt_ret_t my_read(salt_io_channel_t *p_rchannel)
{
    int cport_nr = *((int *) p_rchannel->p_context);
    int bytes_received;
//Receiving messages through cport_nr
    int begin = 0;
    while (begin < p_rchannel->size_expected){ 
        bytes_received = RS232_PollComport(cport_nr, p_rchannel->p_data, p_rchannel->size_expected);
        if (bytes_received != 0) printf("Received %d bytes\n", bytes_received);

//Addition size of bytes
        begin += bytes_received;
        p_rchannel->size += bytes_received;

#ifdef _WIN32
    Sleep(100);
#else
    usleep(100000);  /* sleep for 100 milliSeconds */
#endif
    }

    return SALT_SUCCESS;   
}


//A function to create a timestamp that is included in sent/receivd messages
static salt_ret_t get_time(salt_time_t *p_time, uint32_t *time)
{
    (void) *p_time;
    struct timeval tv;
    gettimeofday(&tv, NULL);
    uint64_t curr_time = (tv.tv_sec) * 1000 + (tv.tv_usec) / 1000;
    uint32_t rel_time = curr_time % 0xFFFFFFFF;
    *time = rel_time;
    return SALT_SUCCESS;
}

