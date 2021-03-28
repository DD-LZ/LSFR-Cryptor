/*  Implemented by Leon Zhu - Leonzhu@umbc.edu
    Github: DD-LZ

    Decrypt KDB files using the decryption algorithm from C1.
    Accepts a KDB file path as first argument in command line.
    Standard outs the decrypted data in the console.
    
*/

#ifndef C2_H
#define C2_H

#include "C1.h"
#include <iostream>
#include <fstream>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

//KDB File Specifications
#define MAX_ENTRIES 127
#define NAME_SIZE 16
#define BLOCK_PTR_SIZE 4
#define MAX_BLOCKS 255
#define DATA_SIZE 2
#define DATA_PTR_SIZE 4


//Main Decryption class
class Decryptor {

    private:
        //Values to keep track of all found data in KDB file
        //Intitial value is default set for challenge requirements
        unsigned int m_InitialValue = 0x4F574154;
        int m_EntryLen = 0;
        int m_NumBlocks[MAX_BLOCKS];
        int m_DataSizes[MAX_BLOCKS][MAX_BLOCKS];
        std::string m_BlockStrs[MAX_ENTRIES];
        unsigned int m_BlockAddresses[MAX_ENTRIES];
        unsigned int m_DataAddresses[MAX_BLOCKS][MAX_BLOCKS];

    public:
        //Reads the passed buffer for processing data locations/information,
        //according to KDB file specifications
        void ReadData(const unsigned char buffer[], int length);

        //Decrypts the data in passed buffer using stored information from ReadData(), 
        //standard outs decrypted data
        void DecryptData(const unsigned char buffer[]);

};

#endif