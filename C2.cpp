/*  Implemented by Leon Zhu - Leonzhu@umbc.edu
    Github: DD-LZ

    Decrypt KDB files using the decryption algorithm from C1.
    Accepts a KDB file path as first argument in command line and 
    standard outs the decrypted data in the console.
        
*/

#include "C2.h"


//Reads the passed buffer for processing data locations/information 
//according to KDB file specifications
void Decryptor::ReadData(const unsigned char buffer[], int length) {

    //Get address of entry list [bytes 6-9]
    unsigned int currPos = (buffer[9]<<24) | (buffer[8]<<16) | (buffer[7]<<8) | buffer[6];
    unsigned int currAddress = 0x00000000;

    //Process through list of entries according to file specification, 
    //Retrieve entry's null-terminated string
    //Retrieve entry's block address
    //Go to next entry, check for end of list
    int count = 0;
    do{

        char blockStr[NAME_SIZE];
        for(int i=currPos; i<(currPos+NAME_SIZE); i++) {
            blockStr[i-currPos] = buffer[i];
        }
        m_BlockStrs[count] = blockStr; 
        currPos = currPos + NAME_SIZE;

        m_BlockAddresses[count] = (buffer[currPos+3]<<24) | (buffer[currPos+2]<<16) | (buffer[currPos+1]<<8) | buffer[currPos];
        if(m_BlockAddresses[count] == 0x00000000) { 
            std::cout << "Detected invalid block address (0x00000000)" << std::endl;
            exit (EXIT_FAILURE);
        }
        currPos = currPos + BLOCK_PTR_SIZE;

        currAddress = (buffer[currPos+3]<<24) | (buffer[currPos+2]<<16) | (buffer[currPos+1]<<8) | buffer[currPos];

        count++;

    }while(currAddress != 0xFFFFFFFF && count <= MAX_ENTRIES);
    m_EntryLen = count;

    //Process through each entry according to file specification,
    //Collect list of blocks
    //Retrieve block's size
    //Retrieve block's data address
    //Go to next entry, check for end of list
    for(int i=0; i<m_EntryLen; i++) {

        currPos = m_BlockAddresses[i];
        count = 0;

        do{

            m_DataSizes[i][count] = (buffer[currPos+1]<<8) | buffer[currPos]; 
            currPos = currPos + DATA_SIZE;

            m_DataAddresses[i][count] = (buffer[currPos+3]<<24) | (buffer[currPos+2]<<16) | (buffer[currPos+1]<<8) | buffer[currPos];
            currPos = currPos + DATA_PTR_SIZE;

            currAddress = (buffer[currPos+3]<<24) | (buffer[currPos+2]<<16) | (buffer[currPos+1]<<8) | buffer[currPos];
            count++;

        }while(currAddress != 0xFFFFFFFF && count <= MAX_BLOCKS);
        m_NumBlocks[i] = count;

    }

}


//Decrypts the data in passed buffer using stored information from ReadData(), 
//standard outs decrypted data
void Decryptor::DecryptData(const unsigned char buffer[]) {

    std::cout << "\n---------------\n";

    //Goes through each entry,
    //Goes through each block in entry if applicable
    //Retrieves data and decrypts it
    //Standard outs Block's string and decrypted data
    for(int i=0; i<m_EntryLen; i++) {

        for(int j=0; j<m_NumBlocks[i]; j++) {

            int length = m_DataSizes[i][j];
            int offset = m_DataAddresses[i][j];

            unsigned char data[length];
            for(int k=offset; k<(length+offset); k++) {
                data[k-offset] = buffer[k];
            }
            unsigned char *dataPtr = data;
            unsigned int value = m_InitialValue;

            std::cout << "Block Name: " << m_BlockStrs[i] << std::endl;
            unsigned char* finalData = Crypt(dataPtr, length, value);
            std::cout << "Block Data: ";
            for(int k=0; k<length; k++) {
                std::cout << finalData[k];
            }
    
        }    

        std::cout << "\n---------------\n";

    }

}


//Main processing function, takes KDB file pathway as argument
int main(int argc, char *argv[]) {

    //Load file
    FILE *bFile = fopen(argv[1], "rb"); 

    if(bFile == NULL) {
        std::cout << "Bad file or pathway, try again." << std::endl;
        exit (EXIT_FAILURE);
    }

    if(bFile == NULL) { 
        std::cout << "Bad file" << std::endl;
    }

    //Get file size
    fseek(bFile, 0, SEEK_END);
    int fileSize = ftell(bFile);
    rewind(bFile);

    //Load file into a buffer
    unsigned char buffer[fileSize];
    int bytesRead = fread(buffer, sizeof(unsigned char), fileSize, bFile);
    std::cout << "Bytes read: " << bytesRead << std::endl;
    fclose(bFile);

    //Run Decryptor
    Decryptor testDecryptor;
    testDecryptor.ReadData(buffer, fileSize);
    testDecryptor.DecryptData(buffer);
    fclose(bFile);

    return 0;

}