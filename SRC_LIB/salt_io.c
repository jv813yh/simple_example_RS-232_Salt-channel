/*
 * salt_io.c    v.0.6
 *
 * Input, Output, Timestamp
 *
 * Functions needed for sending/receiving messages, creating 
 * time stamps in the Salt channelv2 protocol on RS-232 interface
 *
 * Windows/Linux  
 *
 * Author-Jozef Vendel  Date- 28.12.2021 
 * KEMT FEI TUKE, Diploma thesis
 * ===============================================
 */

/* ==== Basic libraries for working in C ==== */
#include <unistd.h>
#include <stdio.h>
#include <inttypes.h>
#include <math.h>
#include <stdio.h>
#include <sys/time.h>
#include <string.h>

/* ======= Salt-channel libraries ======= */
#include "salti_util.h"
#include "salt_io.h"

/* ======= RS-232 library ======= */
#include "rs232.h"

/* ====== Public macro definitions ======= */

/* sleep for 100 milliSeconds - WINDOWS */
#define MILISECONDS_WIN     100

/* sleep for 100 milliSeconds - LINUX */
#define MILISECONDS_LIN      100000

/**
 * The salt-channel-c implements a delay attack protection. This means that both peers
 * sends a time relative to the first messages sent. This means that from the timestamp
 * in a package an expected time could be derived. If this one differs more than the
 * threshold a delay attack might be present and the salt-channel implementation
 * will return error. For this feature to work the used must inject a get time 
 * implementation.
 */

static salt_ret_t get_time(salt_time_t *p_time, uint32_t *time);

salt_time_t my_time = {
    get_time,
    NULL
};

/* ====== Function for sending messages ======= */

salt_ret_t my_write(salt_io_channel_t *p_wchannel)
{
    /* /dev/ttyS0 (COM1 on windows) port */
    int cport_nr = *((int *) p_wchannel->p_context);

    /* Auxiliary variables */
    int bytes_sent = 0, begin = 0; 
    
/**
 * Sends multiple bytes via the cport_nr. p_wchannel->p_data + begin is
 * a pointer to a buffer and p_wchannel->size_expected - begin is the size 
 * of the buffer in bytes.
 * 
 * Returns -1 in case of an error, otherwise it returns the amount of bytes sent.
 * This function blocks (it returns after all the bytes have been processed).
 * 
 */ 
    while (begin < p_wchannel->size_expected) { 
        bytes_sent = RS232_SendBuf(cport_nr, p_wchannel->p_data + begin, p_wchannel->size_expected - begin);
        if (bytes_sent != 0)
            printf("Sent %d bytes.\n", bytes_sent);

//Addition size of bytes
        begin += bytes_sent;  
        p_wchannel->size += bytes_sent;

#ifdef _WIN32
    Sleep(MILISECONDS_WIN); 
#else
    usleep(MILISECONDS_LIN);  
#endif
    }

    return SALT_SUCCESS; 
}

/* ====== Function for receiving messages ======= */

salt_ret_t my_read(salt_io_channel_t *p_rchannel)
{
    /* /dev/ttyS0 (COM1 on windows) port */
    int cport_nr = *((int *) p_rchannel->p_context);

    /* Auxiliary variables */
    int bytes_received, begin = 0;

/**
 * Gets characters from the cport_nr. p_rchannel->p_data is a pointer to a buffer
 * and p_rchannel->size_expected is the size of the buffer in bytes.
 *
 * Returns the amount of received characters into the buffer. 
 * This can be less than size or zero!
 * 
 * It does not block or wait, it returns immediately, 
 * no matter if any characters have been received or not.
 *
 */

    while (begin < p_rchannel->size_expected){ 
        bytes_received = RS232_PollComport(cport_nr, p_rchannel->p_data, p_rchannel->size_expected);
        if (bytes_received != 0) printf("Received %d bytes\n", bytes_received);

//Addition size of bytes
        begin += bytes_received;
        p_rchannel->size += bytes_received;

#ifdef _WIN32
    Sleep(MILISECONDS_WIN); 
#else
    usleep(MILISECONDS_LIN);  
#endif
    }

    return SALT_SUCCESS;   
}


/* A function to create a timestamp that is included in sent/receivd messages */
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

