/*  Implemented by Leon Zhu - LZhu7080@gmail.com
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

#include "C1.h"

//Encrypt/Decrypt data, returns unsigned char array with data
unsigned char *Crypt(unsigned char *data, int dataLength, unsigned int initialValue) {

    //Store values for processing
    //feedbackVal is default set for challenge requirements
    std::bitset<32> feedbackVal(0x87654321);
    std::bitset<32> value(initialValue);
    std::bitset<8> keyBytes;
    unsigned char *newBytes = data;

    //Loop for all data
    for( int i=0; i < dataLength; i++ ) {

        //Step 8 times
        keyBytes.reset();
        for( int j=0; j < 8; j++ ) {

            if(value.test(0)) {
                value = ((value >> 1) ^ feedbackVal);
            }
            else {
                value = (value >> 1);
            }

        }

        //Save key byte
        for( int k=0; k < 8; k++ ) {

            if(value.test(k)) {
                keyBytes.set(k, 1);
            }

        }

        //Unsigned char data is converted to bitset to XOR with keybyte, 
        //then converted back into unsigned char to return to data array
        std::bitset<8> temp(newBytes[i]);
        temp = (temp ^ keyBytes);
        unsigned long templ = temp.to_ulong(); 
        unsigned char newByte = static_cast<unsigned char>( templ );
        newBytes[i] = newByte;

    }

    return(newBytes);

}

/*
//Test run
int main() {

    unsigned char data[] = "apple";
    int dataLen = 5;

    unsigned int initialValue = 0x12345678;

    std::cout << "Encrypting..." << std::endl;
    unsigned char* finalKeyBytes = Crypt(data, dataLen, initialValue);
    std::cout << "Finished Encrypting, Result: ";
    for(int i=0; i < dataLen; i++) {

        std::cout << std::hex << std::uppercase << static_cast<int>(finalKeyBytes[i]);

    } 
    std::cout << std::endl;
  
    std::cout << "Decrypting..." << std::endl;
    unsigned char* finalKeyBytes2 = Crypt(finalKeyBytes, dataLen, initialValue);
    std::cout << "Finished Decrypting, Result: " << finalKeyBytes2 << std::endl;

    return 0;

}
*/
