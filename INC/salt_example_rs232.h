/* 
 * @file salt_example_rs-232.h 	v.0.6
 *
 * KEMT FEI TUKE, Diploma thesis
 *
 * Created auxiliary functions for working with RS-232.
 * The functions are used for transfer between two PCs, 
 * where PC1 reads or creates a file and sends it in 
 * blocks to PC2. The whole process will be performed 
 * and according to the evaluation it will either end 
 * (in case of success) or it will be repeated until 
 * it is successful.
 *
 * Cryptographic protection is provided by the Salt channel protocol
 *
 * Works with functions I demonstrate in source codes 
 * client00.c an server00.c
 *
 * Windows/Linux  
 *
 * Author-Jozef Vendel  Create Date- 02.04.2022 
 */

#ifndef salt_example_rs232_H
#define salt_example_rs232_H

/* ===== Salt-channel libraries ===== */

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
 *
 * read / write  process state machine,
 * encrypts and wraps clear text data,
 * unwraps and decrypts a salt channel package,
 * auxiliary functions for reading 
 * and writing data (clear / encrypt / decrypt)
 * and others ....
 */
#include "salti_util.h"

/** 
* Delay attack protection, 
* threshold for differense in milliseconds. 
*/

/* ========= MACRO ==============*/

/** 
* Delay attack protection, 
* threshold for differense in milliseconds. 
*/
#define TRESHOLD              3000

/* Encryption buffer overhead size for read */
#define SALT_READ_OVRHD_SIZE    38   

/* Encryption buffer overhead size for write */  
#define SALT_WRITE_OVRHD_SIZE   42   

/* AUXILIARY FIELDS SIZE */
#define STATIC_ARRAY          1024

/* 
 * Supported protocol of salt-channel. 
 * The user support what protocols is used by the
 * salt-channel.
 */
#define PROTOCOL_BUFFER       128	


/* =========================== FUNCTIONS ===================== */

/* 
 * The sleep() method, which suspends the implementation of the program
 * for a specified number of seconds.
 *
 * @param  sleep_milisecond   Number of milliseconds
 * @return 1		      In case of success
 */
uint32_t sleep_miliseconds_win_linux(int sleep_miliseconds);

/*
 * Function for creating / loading input file. 
 *
 * @return  pointer to the stream(file)
 */
uint8_t *loading_file(char *file, 
                      uint32_t *file_size, 
                      int my_file);

/* 
 * Function for buffer preparation, data too, 
 * encryption and data sending (in Salt channel) for client and server.
 *
 * @par p_channel:       pointer to salt_channel_t structure
 * @par p_buffer:        buffer for encryption
 * @par size_buffer:     size of buffer
 * @par file_size:       size of data what we want encrypt and send
 * @par block_size:      size of block 
 * @par p_input:         input data 
 * @par p_msg:           pointer to salt_msg_t structure
 *
 * @return SALT_SUCCESS          in case success
 * @return SALT_ERROR
 * @return SALT_PENDING
 */
uint32_t salt_encrypt_and_send(salt_channel_t *p_channel,
                               uint8_t *p_buffer,
                               uint32_t size_buffer,
                               uint32_t file_size,
                               uint32_t block_size,
                               uint8_t *p_input,
                               salt_msg_t *p_msg);

/* 
 * Function for data receiving, decryption, verify and
 * read them (in Salt channel) for server.
 *
 * @par p_channel:       pointer to salt_channel_t structure
 * @par p_buffer:        buffer for encryption
 * @par size_buffer:     size of buffer
 * @par p_msg:           pointer to salt_msg_t structure
 * @par *p_coppy_buffer  buffer, where is data copy
 * @par *p_decrypt_size  decrypt size of decryption data
 * @par *fp		 file, where is decrypted data stored 
 *
 * @return 1         in case success
 */
uint32_t salt_read_and_decrypt_server(salt_channel_t *p_channel,
                                        uint8_t *p_buffer,
                                        uint32_t size_buffer,
                                        salt_msg_t *p_msg,
                                        uint8_t *p_coppy_buffer,
                                        uint32_t *p_decrypt_size,
                                        FILE *fp);

/* 
 * Function for Salt channel protocol deployment for the client 
 * and connection establishment (Salt handshake).
 *
 * @par p_client_channel:       pointer to salt_channel_t structure
 * @par write_impl:             write implementation 
 * @par read_impl:              read implementation 
 * @par p_cport_nr:             number of port
 * @par p_time_impl             time implementation
 * @par treshold                value for threshold
 *
 * @return SALT_SUCCESS          in case success
 * @return SALT_ERROR
 * @return SALT_PENDING
 */
salt_ret_t salt_impl_and_hndshk(salt_channel_t *p_channel, 
                                    salt_io_impl write_impl,
                                    salt_io_impl read_impl,
                                    int *p_cport_nr,
                                    salt_time_t *p_time_impl,
                                    uint32_t treshold); 

/* 
 * Function for Salt channel protocol deployment for the server 
 * and connection establishment (Salt handshake).
 *
 * @par p_server_channel:       pointer to salt_channel_t structure
 * @par p_protocols:            version of protocol
 * @par write_impl:             write implementation 
 * @par read_impl:              read implementation 
 * @par p_cport_nr:             number of port
 * @par p_time_impl             time implementation
 * @par p_signature             array with signature
 * @par treshold                value for threshold
 *
 * @return SALT_SUCCESS          in case success
 * @return SALT_ERROR
 * @return SALT_PENDING
 */
salt_ret_t salt_impl_and_hndshk_server(salt_channel_t *p_server_channel,
                                    salt_protocols_t *p_protocols, 
                                    salt_io_impl write_impl,
                                    salt_io_impl read_impl,
                                    int *p_cport_nr,
                                    salt_time_t *p_time_impl,
                                    const uint8_t *p_signature,
                                    uint32_t treshold); 

/* 
 * Function for writing small messages secured and sent by the protocol.
 *
 * @par p_channel:       	pointer to salt_channel_t structure
 * @par p_data:            	message
 * @par size_data,:             size of message
 * @par size_buffer             size of buffer for encryption
 *
 * @return 1          		in case success
 */
uint32_t salt_write_small_messages(salt_channel_t *p_channel,
                            	   uint8_t *p_data,
                            	   uint32_t size_data,
                            	   uint32_t size_buffer);

/* 
 * Function for reading small messages receiving and decrypted by the protocol.
 * It can also read the expected size of transmitted data sent 
 * using the function salt_convert_size_and_send().
 *
 * @par p_channel:       	pointer to salt_channel_t structure
 * @par p_buffer		buffer for stored encryption message
 * @par buffer_size 		buffer size
 * @par p_msg             	pointer to salt_msg_t structure
 * @par p_expceted_size         reading the expected size
 * @par read_convert_size	1 or 0, 0-> you dont want to read the size
 *
 * @return 1          		in case success
 */
uint32_t salt_read_small_messages(salt_channel_t *p_channel,
                                 uint8_t *p_buffer,
                                 uint32_t buffer_size,
                                 salt_msg_t *p_msg,
                                 uint32_t *p_expceted_size,
                                 uint32_t read_convert_size);

/* 
 * It calculates the size of the data and sends a secure size message using a protocol.
 *
 * @par p_channel:       	pointer to salt_channel_t structure
 * @par convert_size:		Calculated size, which is send
 *
 * @return 1          		in case success
 */
uint32_t salt_convert_size_and_send(salt_channel_t *p_channel,
                                    uint32_t convert_size);  


#endif
