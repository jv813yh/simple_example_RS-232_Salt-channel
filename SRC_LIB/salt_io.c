/*
 * salt_io.c    v.0.7
 *
 * Input, Output, Timestamp
 *
 * Functions needed for sending/receiving messages, creating 
 * time stamps in the Salt channelv2 protocol on RS-232 interface
 *
 * Windows/Linux  
 *
 * Author-Jozef Vendel  Date- 28.12.2021 
 *
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
/* RS-232 : created auxiliary functions for Salt protocol */
#include "salt_example_rs232.h"

/* ====== Public macro definitions ======= */

/* Sleep for 50 milliSeconds  */
#define MILISECONDS            50

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

    /* Size of bytes sent */
    int32_t bytes_sent = 0, sleep_return;
 
    /* The amount of data to send */
    uint32_t to_write = p_wchannel->size_expected - p_wchannel->size;
    
/**
 * Sends multiple bytes via the cport_nr. &p_wchannel->p_data[p_wchannel->size] 
 * is a pointer to a buffer and to_write is the size of the buffer in bytes.
 * 
 * Returns -1 in case of an error, otherwise it returns the amount of bytes sent.
 * This function blocks (it returns after all the bytes have been processed).
 * 
 */ 
   
    bytes_sent = RS232_SendBuf(cport_nr,
                               &p_wchannel->p_data[p_wchannel->size], 
                               to_write);
    
    if (bytes_sent != 0)
        printf("Sent %d bytes.\n", bytes_sent);

    if (bytes_sent < 0) 
    {
        p_wchannel->err_code = SALT_ERR_CONNECTION_CLOSED;
        printf("-1 bytes were sent, the connection is closed\n");

        return SALT_ERROR;
    }

    SALT_HEXDUMP_DEBUG(&p_wchannel->p_data[p_wchannel->size], bytes_sent);
       
    /* Addition sent size of bytes */
    p_wchannel->size += bytes_sent;

    if ((sleep_return = sleep_miliseconds_win_linux(MILISECONDS)) == 0)
    {
        printf("Problem during sleep I/O");
        return SALT_ERROR;
    }

    return (p_wchannel->size == p_wchannel->size_expected) ? SALT_SUCCESS : SALT_PENDING;
}

/* ====== Function for receiving messages ======= */

salt_ret_t my_read(salt_io_channel_t *p_rchannel)
{
    /* /dev/ttyS0 (COM1 on windows) port */
    int cport_nr = *((int *) p_rchannel->p_context);

    /* Size of bytes received */
    int32_t bytes_received = 0, sleep_return;

    /* The amount of data to received */
    uint32_t to_read;

/**
 * Gets characters from the cport_nr. &p_rchannel->p_data[p_rchannel->size]
 * is a pointer to a buffer and to_read is the size of the buffer in bytes.
 *
 * Returns the amount of received characters into the buffer. 
 * This can be less than size or zero!
 * 
 * It does not block or wait, it returns immediately, 
 * no matter if any characters have been received or not
 * therefore, this cycle: while (p_rchannel->size < p_rchannel->size_expected){}
 * is needed !!!
 */
   while (p_rchannel->size < p_rchannel->size_expected)
    { 
        /* The amount of data to received */
        to_read = p_rchannel->size_expected - p_rchannel->size;
       
        bytes_received = RS232_PollComport(cport_nr, 
                                           &p_rchannel->p_data[p_rchannel->size],
                                           to_read);
        if (bytes_received >= 4000)
        {
            if ((sleep_return = sleep_miliseconds_win_linux(MILISECONDS)) == 0)
            {
                printf("Problem during sleep I/O");
                return SALT_ERROR;
            }
        }

        SALT_HEXDUMP_DEBUG(&p_rchannel->p_data[p_rchannel->size], bytes_received);

        /* Addition size of bytes */
        p_rchannel->size += bytes_received;

        if (bytes_received != 0) 
            printf("Received %d bytes\n", bytes_received);

        if (bytes_received < 0) 
        {
            p_rchannel->err_code = SALT_ERR_CONNECTION_CLOSED;
            printf("-1 bytes were received, the connection is closed\n");

            return SALT_ERROR;
        }
    } /* End of  while (p_rchannel->size < p_rchannel->size_expected) {....} */

   // SALT_HEXDUMP_DEBUG(&p_rchannel->p_data[p_rchannel->size], bytes_received);

    if ((sleep_return = sleep_miliseconds_win_linux(MILISECONDS)) == 0)
    {
        printf("Problem during sleep I/O");
        return SALT_ERROR;
    }

    return (p_rchannel->size == p_rchannel->size_expected) ? SALT_SUCCESS : SALT_PENDING;
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

