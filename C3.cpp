/*  Implemented by Leon Zhu - LZhu7080@gmail.com
    Github: DD-LZ

    Discovery, recovery, and patching of hidden JPEG files. 
    Decrypt data from KDB file to use in discovering hidden JPEG files in a file.
    Decrypt KDB files using the decryption algorithm from C1.
    Accepts 2 pathway arguments of a KDB file and a file containing the hidden JPEG files.
    Standard outs information about found JPEG files and stores them in a separate directory.

*/

#include "C3.h"


//Calculate MD5 hash of file using modified implementation
std::string JpegSaver::getMD5Hash(std::string filename) {

    std::ifstream file;
    file.open (filename, std::ios::binary | std::ios::in);

    file.seekg (0, std::ios::end);
    long fileLen = file.tellg();
    file.seekg (0, std::ios::beg);    

    char * fileData = new char[fileLen];
    file.read(fileData, fileLen);

    std::string temp =  md5(fileData, fileLen);
    delete [] fileData;
    
    return temp;

}


//Process KDB file to recover magic bytes to recover hidden JPEG files
//Based off functions of challenge 2
unsigned char *JpegSaver::getMagicBytes(std::string magicFile) {

    //Load file into a buffer
    FILE *bFile = fopen(magicFile.c_str(), "rb"); 
    if(bFile == NULL) {
        std::cout << "Bad file or pathway, try again." << std::endl;
        exit (EXIT_FAILURE);
    }
    fseek(bFile, 0, SEEK_END);
    int fileSize = ftell(bFile);
    rewind(bFile);
    unsigned char buffer[fileSize];
    fread(buffer, sizeof(unsigned char), fileSize, bFile);
    fclose(bFile);

    //Process of retrieving data and decypting from KDB file borrowed from challenge 2
    //Only one data is retrieved so no loop implemented for multiple entries needed
    //Go to entry list, go to block (name not needed), retrieve block data and decrypt
    unsigned int currPos = (buffer[9]<<24) | (buffer[8]<<16) | (buffer[7]<<8) | buffer[6];
    currPos = currPos + NAME_SIZE;

    unsigned int blockAddress = (buffer[currPos+3]<<24) | (buffer[currPos+2]<<16) | (buffer[currPos+1]<<8) | buffer[currPos];
    currPos = blockAddress;

    unsigned int dataSize = (buffer[currPos+1]<<8) | buffer[currPos]; 
    currPos = currPos + BLOCK_SIZE;

    unsigned int dataAddress = (buffer[currPos+3]<<24) | (buffer[currPos+2]<<16) | (buffer[currPos+1]<<8) | buffer[currPos];
    unsigned char data[dataSize];
    for(unsigned int i=dataAddress; i<(dataSize+dataAddress); i++) {
        data[i-dataAddress] = buffer[i];
    }
    unsigned char *dataPtr = data;
    unsigned int value = m_InitialValue;

    //Decrypt starting magic bytes and store along with ending magic bytes
    unsigned char *magicBytes = (unsigned char*) malloc(5);
    memcpy(magicBytes, Crypt(dataPtr, dataSize, value), 3);
    magicBytes[3] = 0xFF;
    magicBytes[4] = 0xD9;

    return magicBytes;

}


//Process the file using the magic bytes from getMagicBytes()
//Locates and saves JPEGs location for recovery
void JpegSaver::getJPEGs(std::string inputFile, unsigned char *magicBytes) {

    //Load file into a buffer
    FILE *bFile = fopen(inputFile.c_str(), "rb"); 
    if(bFile == NULL) {
        std::cout << "Bad file or pathway, try again." << std::endl;
        exit (EXIT_FAILURE);
    }
    fseek(bFile, 0, SEEK_END);
    int fileSize = ftell(bFile);
    rewind(bFile);
    unsigned char buffer[fileSize];
    fread(buffer, sizeof(unsigned char), fileSize, bFile);
    fclose(bFile);

    //Search through the buffer looking for sections that start and end with the
    //known custom magic bytes and store their locations
    int count = 0;
    while(true) {

        //Search for starting magic bytes
        while(true){
            
            m_SearchBytes[0] = buffer[count];
            m_SearchBytes[1] = buffer[count+1];
            m_SearchBytes[2] = buffer[count+2];

            //EOF
            if((count+2) >= fileSize) { break; }

            if(m_SearchBytes[0] == magicBytes[0] && m_SearchBytes[1] == magicBytes[1] && m_SearchBytes[2] == magicBytes[2]) {
                m_Locations[m_NumJPEGs][0] = count;
                count++;
                break;
            }

            count++;

        }

        //Search for ending magic bytes
        while(true){
            
            m_SearchBytes[0] = buffer[count];
            m_SearchBytes[1] = buffer[count+1];

            //EOF
            if((count+1) >= fileSize) { break; }

            if(m_SearchBytes[0] == magicBytes[3] && m_SearchBytes[1] == magicBytes[4]) {
                m_Locations[m_NumJPEGs][1] = count+2;
                m_NumJPEGs++;
                count++;
                break;
            }

            count++;

        }

        //EOF
        if((count+1) >= fileSize) { break; }

    }

}


//Recovers hidden JPEG files from recovered locations and patches them 
//Standard outs information on each JPEG found and stores them in a separate directory
void JpegSaver::saveJPEGs(std::string inputFile) {

    //Load file into a buffer
    FILE *bFile = fopen(inputFile.c_str(), "rb"); 
    if(bFile == NULL) {
        std::cout << "Bad file or pathway, try again." << std::endl;
        exit (EXIT_FAILURE);
    }
    fseek(bFile, 0, SEEK_END);
    int fileSize = ftell(bFile);
    rewind(bFile);
    unsigned char buffer[fileSize];
    fread(buffer, sizeof(unsigned char), fileSize, bFile);
    fclose(bFile);

    //Create directory
    std::string dirName = inputFile + "_Repaired";
    if(!mkdir(dirName.c_str())) { std::cout << "\nDirectory made: " << dirName << std::endl << std::endl; }
    else { std::cout << "\nDirectory creation failed, perhaps directory already exists?\n" << std::endl; }

    //Recover JPEGs using earlier location data, 
    //Patch and create JPEG files
    //Standard out information
    for(int i=0; i<m_NumJPEGs; i++) {

        unsigned int jpegSize = (m_Locations[i][1] - m_Locations[i][0]);
        unsigned char contents[jpegSize];

        for(int j=0; j<jpegSize; j++) {

            contents[j] = buffer[m_Locations[i][0]+j];

        }

        contents[0] = 0xFF;
        contents[1] = 0xD8;
        contents[2] = 0xFF;

        std::string jpegName = dirName + "\\" + std::to_string(m_Locations[i][0]) + ".jpeg";
        FILE *newFile = fopen(jpegName.c_str(), "wb");
        fwrite(contents, sizeof(unsigned char), jpegSize, newFile);
        fclose(newFile);
    
        std::string md5Hash = getMD5Hash(jpegName);

        std::cout << "---Created JPEG---" << std::endl;
        std::cout << "Offset: " << std::hex << m_Locations[i][0] << std::dec << " (" << m_Locations[i][0] << ")" << std::endl;
        std::cout << "Size: " << jpegSize << std::endl;
        std::cout << "MD5 Hash: " << md5Hash << std::endl;
        std::cout << "Location: " << jpegName << std::endl;
        std::cout << std::endl;

    }

}


//Main processing function, takes 2 file pathway arguments, a KDB file and file to search
int main(int argc, char *argv[]) {

    JpegSaver aJpegSaver;
    unsigned char *magicBytes = aJpegSaver.getMagicBytes(argv[1]);
    aJpegSaver.getJPEGs(argv[2], magicBytes);
    aJpegSaver.saveJPEGs(argv[2]);
    free(magicBytes);

    return 0;

}
