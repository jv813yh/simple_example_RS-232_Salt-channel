# simple_example_RS-232_Salt-channel

Demonstration of an example using the RS-232 communication channel p
implementation of the salt-channelv2 application cryptographic protocol
in C. The client.exe application loads the input file and initiates a salt handshake
between the clientand server.
The client also sends to the server the size of the transferred file and 
the size of the blocks in which the file is transferred.
If the salt handshake is successful, it is safe
client-server connection. The client sends the loaded file to the server
, the server receives it, decrypts it and displays it on the screen.
Success is verified using the SALT_SUCCESS and SALT_ERROR protocol constants
transmitted data. If the whole process is successful, the server sends it
to the client confirming the message that the data exchange took place correctly, if not
sends him that the data exchange did not work properly and the data exchange process is necessary
to repeat. Data is received and sent within the COM ports (number,
needs to be adjusted in source codes).The integrity of the transmitted data is being verified.

Data is transferred in multiple blocks.
It should be borne in mind that for what distance the data is transmitted, what RS232 parameters
it has it set and how much data is being transferred so that the situation does not happen
I will not be able to write data and I will come, in this case I will lose data. 
It should be safe against this case.
The program was tested with a maximum size of 11MB.

The program can be compiled using the Makefile file. I added .bat files for Windows.
A feature has been added
to load the input file that is being sent, the function is also executed
operation if the user wants to create his own test file and send it through the channel.

# Windows/Linux
I use the emulator on Windows to simulate RS-232 hardware interfaces:
https://www.ai-media.tv/wp-content/uploads/2019/07/com0com_setup.pdf

On Linux You need to assign to the "dialout" group and have active ports.

# Salt-channel:
Discription about salt-channel: 
https://github.com/assaabloy-ppi/salt-channel-c
The salt channel protocol is powered by the tweetNaCl cryptographic library:
https://tweetnacl.cr.yp.to/


