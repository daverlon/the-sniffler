#include <iostream>
#include <string>
#include <sstream>
#include <fstream>
#include <iomanip>
#include <vector>

using namespace std;

#include "icekey.h"
#include "bitread.h"

constexpr char hexmap[] = { '0', '1', '2', '3', '4', '5', '6', '7',
                           '8', '9', 'a', 'b', 'c', 'd', 'e', 'f' };

string bytesToHexStr(const unsigned char* data)
{
    int len = 8;
    string s(len * 2, ' ');
    for (int i = 0; i < len; ++i) {
        s[2 * i] = hexmap[(data[i] & 0xF0) >> 4];
        s[2 * i + 1] = hexmap[data[i] & 0x0F];
    }
    return s;
}

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

void displayBytes(unsigned char* data) {
    int len = 8;
    for (int i = 0; i < 8; ++i) {
        cout << static_cast<int>(data[i]) << ' ';
    }
    cout << endl;
}

int debug = 1;

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

	if (argc != 3) {
		cerr << "Must provide function and hex string as arguments. Example: decompress 1a1b1c1d1a1b1c1d" << endl;
        cerr << "Functions: decrypt, decompress" << endl;
		return 1;
	}


    std::string function = argv[1];

	string payloadstr = argv[2];

	// convert payload (hex str) to bytes*
	vector<uint8_t> payloadbytesvec = hexStringToBytes(payloadstr);
	uint8_t* payloadbytes = payloadbytesvec.data();

    if (function == "decrypt") {

        int n = 0;
        string keystr = "d7NSuLq2"; // perhaps convert to bytes? idk
        // (encrypted payload)
        //string payloadstr = "1a1b1c1d1a1b1c1d"; // (hex) ---> ??? (hex)

        // convert key to bytes*
        uint8_t* keybytes = (uint8_t*)keystr.c_str();

        // setup icekey
        IceKey ik(n);
        ik.set(keybytes);

        uint8_t dec[8];
        ik.decrypt(payloadbytes, dec);

        // encrypt it again to ensure that it matches the original
        uint8_t enc[8];
        ik.encrypt(dec, enc);

        //cout << bytesToHexStr(enc) << endl;
        if (bytesToHexStr(enc) != payloadstr) {
            cerr << "ERROR: Mismatch between input ciphertext and output ciphertext:" << endl;
            cerr << payloadstr << endl;
            cerr << bytesToHexStr(enc) << endl;
            return 1;
        }

        cout << bytesToHexStr(dec);
    }
    else if (function == "decompress") {

        // decompress it
        CLZSS s;
        if (s.IsCompressed(payloadbytes)) {
            if (debug)
                cout << "Compressed packet.";
        }
        else {
            if (debug)
                cout << "Not compressed packet.";
        }
    }


    return 0;
}