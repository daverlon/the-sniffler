#include <iostream>
#include <string>
#include <sstream>
#include <fstream>
#include <iomanip>
#include <vector>

using namespace std;

#include "bitread.h"

std::vector<uint8_t> hexStringToBytes(const std::string& hexString) {
    std::vector<uint8_t> bytes;

    // Iterate over pairs of characters in the hex string
    for (std::size_t i = 0; i < hexString.length(); i += 2) {
        // Extract two characters from the hex string
        std::string byteString = hexString.substr(i, 2);

        // Convert the two characters to an actual byte (uint8_t)
        uint8_t byte = static_cast<uint8_t>(std::stoi(byteString, nullptr, 16));

        // Add the byte to the vector
        bytes.push_back(byte);
    }

    return bytes;
}

int main(int argc, char* argv[]) {

    // argv[1] = data

    if (argc != 2) {
        cerr << "Error: incorrect usage." << endl;
        cerr << "Example usage: lzss.exe 1a1b1c1d1a1b1c1d" << endl;
        return 1;
    }
	string payloadstr = argv[1];
	vector<uint8_t> payloadbytesvec = hexStringToBytes(payloadstr);

	uint8_t* payloadbytes = payloadbytesvec.data();

    CLZSS s;
    if (s.IsCompressed(payloadbytes)) {
        cout << "YYY COMPRESSED FOUND";
    }
    else {
        cout << "NNN NOT COMPRESSED";
    }

    return 0;
}