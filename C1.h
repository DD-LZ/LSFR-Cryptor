/*  Implemented by Leon Zhu - Leonzhu@umbc.edu
    Github: DD-LZ

    Implementation of file encrypting and decrypting using an LSFR algorithm 
    on an initial value followed by an XOR with data.

    LSFR algorithm steps:
        1. Start with an initial value and feedback value
        2. Step 8 times, each time modifying initial value according to lowest bit: 
                bit = 0: value = value >> 1
                bit = 1: value = (value >> 1) ^ Feedback
        3. XOR data with lowest byte of initial value after 8 steps
        4. Repeat steps 2 and 3 until all data is processed

*/

#ifndef C1_H
#define C1_H

#include <iostream>
#include <bitset>

//Encrypt/Decrypt data, returns unsigned char array with data
unsigned char *Crypt(unsigned char *data, int dataLength, const unsigned int initialValue);

#endif