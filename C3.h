/*  Implemented by Leon Zhu - LZhu7080@gmail.com
    Github: DD-LZ

    Discovery, recovery, and patching of hidden JPEG files. 
    Decrypt data from KDB file to use in discovering hidden JPEG files in a file.
    Decrypt KDB files using the decryption algorithm from C1.
    Accepts 2 pathway arguments of a KDB file and a file containing the hidden JPEG files.
    Standard outs information about found JPEG files and stores them in a separate directory.

*/

#ifndef C3_H
#define C3_H

#include "C1.h"
#include <iostream>
#include <fstream>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

//Original MD5 Hash Implementation by Frank Thilo: http://www.zedwood.com/article/cpp-md5-function
//Using modified implementation found here: https://github.com/alm4096/MD5-Hash-Example-VS/tree/master/MD5
#include "md5.h"

//KDB File Specifications
#define MAX_ENTRIES 127
#define NAME_SIZE 16
#define MAX_BLOCKS 255
#define BLOCK_PTR_SIZE 4
#define BLOCK_SIZE 2
#define DATA_PTR_SIZE 4


//Main JPEG Recoverer class
class JpegSaver {

    private:
        //Values to keep track of all found data in file
        //Intitial value is default set for challenge requirements
        unsigned int m_InitialValue = 0x4F574154;
        int m_NumJPEGs = 0;
        unsigned char m_SearchBytes[3];
        unsigned int m_Locations[255][2];

    public:
        //Calculate MD5 hash of file using modified implementation
        std::string getMD5Hash(std::string filename);

        //Process KDB file to recover magic bytes to recover hidden JPEG files
        //Based off functions of challenge 2
        unsigned char *getMagicBytes(std::string magicFile);

        //Process the file using the magic bytes from getMagicBytes()
        //Locates and saves JPEGs location for recovery
        void getJPEGs(std::string inputFile, unsigned char *magicBytes);

        //Recovers hidden JPEG files from recovered locations and patches them 
        //Standard outs information on each JPEG found and stores them in a separate directory
        void saveJPEGs(std::string inputFile);

};

#endif
