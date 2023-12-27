#include <iostream>
#include <string>
#include <sstream>
#include <fstream>
#include <iomanip>
#include <vector>

using namespace std;

#include "icekey.h"

int main(int argc, char* argv[]) {

    /*
        defaults:
        n = 2
        key = d7NSuLq2
        hexstr = 1a1b1c1d1a1b1c1d ---> 5d d7 b9 1a 9f 69 fd a1 (note: test this further?)
    */

    /*
		argv[0]: icekey n value
        argv[1]: icekey key
        argv[2]: hex string (8 bytes)
    
    */

    int n = 2;
    string key = "d7NSuLq2"; // perhaps convert to bytes? idk
    string hexString = "1a1b1c1d1a1b1c1d"; // ---> 5d d7 b9 1a 9f 69 fd a1

    IceKey ik(n);

    // convert std::strings to unsigned const char*
    const unsigned char* ucckey = reinterpret_cast<const unsigned char*>(key.c_str());
    const unsigned char* uccstr = reinterpret_cast<const unsigned char*>(hexString.c_str());

    ik.set(ucckey);

    unsigned char buff[8] = {};
    ik.decrypt(uccstr, buff);

    //displaybytes(buff);

    // Print the bytes in decimal format
    for (size_t i = 0; i < sizeof(buff) / sizeof(buff[0]); ++i) {
        std::cout << static_cast<int>(buff[i]) << ' ';
    }
    std::cout << std::endl;

    return 0;
}