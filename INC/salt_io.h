/*
 * Input, Output, Timestamp
 *
 * Functions needed for sending/receiving messages, creating time stamps 
 * in the Salt channelv2 protocol on RS-232 interface
 *
 * Windows/Linux  
 *
 * KEMT FEI TUKE, Diploma thesis
 *
 * Author Jozef Vendel, Create date 02.04.2022
 */

#ifndef SALT_IO_H
#define SALT_IO_H

#include "salt.h"

salt_ret_t my_write(salt_io_channel_t *p_wchannel);
salt_ret_t my_read(salt_io_channel_t *p_rchannel);

salt_time_t my_time;

#endif /* SALT_IO_H */
