/*
 * Emilio Borges
 * October - November 8, 2016
 * University of Toledo - Undergrad Computer Science and Engineering
 * Computer Security - DES Programming Assignment
 *
 * Assignment Documentation: https://drive.google.com/open?id=0B4CF__kbczDjMGI0dklnZ2RxVTg
 *
 * Students are to implement the Data Encryption Standard (DES) algorithm and be able to
 * encrypt/decrypt any input file. Look at the assignment doc for more details.
 *
 * Any code not commented should be self explanatory (i.e. self documented) due to its simplicity
 *
 * This program takes 5 arguments, <-action>, <key>, <mode>, <infile>, and <outfile>
 * <-action> = -e to encrypt <infile> or -d to decrypt <infile>
 * <key>     = 8 character string surrounded by single quotes ('Pa$$W0rD') or 64 bit HEX value (without 0x prefix)
 * <mode>    = only ecb mode supported; argument should read "ecb" (without quotes)
 * <infile>  = input file to encrypt or decrypt
 * <outfile> = output file to save encrypted or decrypted data
*/

#include <iostream>
#include <fstream>
#include <time.h>
#include <math.h>

// comment out this define to prevent debugging text from printing to the console
#define DEBUG

using namespace std;

bool encrypt;                   // encrypt (true) or decrypt (false)
uint64_t key;                   // 64 bit DES key (56 bits actually used)
bool ecbMode;                   // should always be true; only ecb mode supported
fstream infile;                 // input file stream
fstream outfile;                // output file stream
uint64_t block;                 // container for our 64 bit block throughout the DES algorithm
uint64_t infile_byte_length;
unsigned int bytes_remaining;   // number of bytes yet to be read
uint64_t roundkey[16];            // storage for the sixteen 48 bit sub keys used throughout DES's sixteen cycles

// function input/output defined with function definition
void print64(uint64_t &value, char type);
void readBlock();
void writeBlock();
void DES();

int main(int argc, char *argv[]) {

    // Help argument; describe acceptable arguments
    if(argc == 2 && !strncmp(argv[1], "help", 4)) {
        cout << "\nDES Help - Acceptable Arguments";
        cout << "\n\n\t<-action> <key> <mode> <infile> <outfile>\n";
        cout << "\n\t\t<-action> -e to encrypt <infile> or -d to decrypt <infile>";
        cout << "\n\t\t<key> 8 character string surrounded by single quotes or 64 bit HEX value (without 0x prefix)";
        cout << "\n\t\t<mode> only ecb mode supported; argument should read \"ecb\" (without quotes)";
        cout << "\n\t\t<infile> input file to encrypt or decrypt";
        cout << "\n\t\t<outfile> output file to save encrypted or decrypted data" << endl;
        return 0;
    }

    // ------------------------------------------------------------------------
    // Validate and sanitize arguments
    // ------------------------------------------------------------------------
    if (argc != 6) {cout << "Invalid argument length!"; return 0;}

    #ifdef DEBUG
    cout << "Arguments:" << endl;
    cout << "\targc = " << argc << endl;
    cout << "\targv[0] = <path>    = " << argv[0] << endl;
    cout << "\targv[1] = <-action> = " << argv[1] << endl;
    cout << "\targv[2] = <key>     = " << argv[2] << endl;
    cout << "\targv[3] = <mode>    = " << argv[3] << endl;
    cout << "\targv[4] = <infile>  = " << argv[4] << endl;
    cout << "\targv[5] = <outfile> = " << argv[5] << endl;

    cout << "\nVariable Values:";
    #endif

    // <-action>
    encrypt = false; // start with assuming we'll decrypt
    // first and last characters in first argument should be the same for selecting encrypt or decrypt
    // 0 = the null terminating character
    if(argv[1][0] != '-' || argv[1][2] != 0)
        {cout << "\nInvalid <-action> argument! Only -e and -d allowed\n"; return 0;}
    if(tolower(argv[1][1]) == 'e') encrypt = true;
    else if(tolower(argv[1][1]) != 'd')
        {cout << "\nInvalid <-action> argument! Only -e and -d allowed\n"; return 0;}
    #ifdef DEBUG
    cout << "\n\tbool encrypt = ";
    if(encrypt) cout << "TRUE" << endl;
    else cout << "FALSE" << endl;
    #endif

    // <key>
    key = 0ULL; // in order to set bits where they should go, our 64 bit key container should be cleared
                // 0ULL = Unsigned Long Long = 64 bit value of all zeros
    // keys will begin with a single quote or a hex digit
    if(argv[2][0] == '\''){
        // go through each bit of the 8 character key ignoring the beginning single quote
        // i = index for character in argv[2]
        for(int i = 1, j = 63; i < 9; ++i){
            // check for short key arguments
            // 0 (null terminating char) will appear at the end of every argument from command line
            if(argv[2][i] == 0)
                {cout << "\nInvalid key length; Key too short!\n"; return 0;}
            if(argv[2][i] == '\'')
                {cout << "\nInvalid key length; Key too short! single quote character not allowed\n"; return 0;}

            // j = index for bit location within 64 bit key container
            // k = index for bit location within a single character
            // go through every bit of every character in argument and set appropriate bits in 64 bit key container
            for(int k = 7; k >= 0; --j, --k) {
                if(argv[2][i] & (1 << k)) key |= (1ULL << j);
            }
        }
        // check for long key arguments
        if((argv[2][9] != '\'' && argv[2][9] != 0) || (argv[2][9] == '\'' && argv[2][10] != 0))
            {cout << "\nInvalid key length; Key too long!\n"; return 0;}
    }
    else if(isxdigit(argv[2][0])){
        // go through argument's 16 hex digits (64 bits)
        for(int i = 0; i < 16; ++i){
            // check for short key arguments or invalid hex digits
            // 0 (null terminating char) will appear at the end of every argument from command line
            if(argv[2][i] == 0) {cout << "\nKey too short! Require 64 bit HEX value (without 0x prefix)\n"; return 0;}
            if(!isxdigit(argv[2][i]))
            {cout << "\nInvalid key! Key is not a HEX value! Require 64 bit HEX value (without 0x prefix)\n"; return 0;}

            // extract numerical hex value from character
            // '0' = 0x30 ascii; '3' - '0' = 0x33 - 0x30 = 0x03 = 3 decimal
            int hex_val = toupper(argv[2][i]) - '0';
            // if character is non-numeric (i.e. 'A', 'B', 'C', ...)
            // 'A' = 0x41; 'A' - '0' - 7 decimal = 0x41 - 0x30 - 0x07 = 0x0A = 10 decimal
            if(hex_val > 9) hex_val -= 7;
            key |= (uint64_t)hex_val << ((15 - i) * 4); // set appropriate bits in 64 bit container
        }
        // check for long key arguments
        if(argv[2][16] != 0) {cout << "\nKey too long! Require 64 bit HEX value (without 0x prefix)\n"; return 0;}
    }
    else {
        cout << "Invalid <key> argument! Must begin with single quote character or HEX value (without 0x prefix)";
        return 0;
    }
    uint64_t badkey1 = 0ULL;
    uint64_t badkey2 = 0xFFFFFFFFFFFFFFFF;
    uint64_t badkey3 = 0xFFFFFFFF00000000;
    uint64_t badkey4 = 0x00000000FFFFFFFF;
    if(key == badkey1 || key == badkey2 || key == badkey3 || key == badkey4)
        {cout << "\nThe key used will not work well with DES. Please choose a better key.\nExiting DES."; return 0;}
    #ifdef DEBUG
    // print 64 bit key value in decimal, binary, hex, and ascii string representation
    cout << "\tuint64_t key = 0d" << key << "\n\t             = ";
    print64(key, 'b');
    cout << "\n\t             = ";
    print64(key, 'x');
    cout << "\n\t             = ";
    print64(key, 's');
    cout << endl;
    #endif

    // <mode>
    // since only ecb mode supported, argv[3] (tolower()) should read 'e','c','b'
    if(tolower(argv[3][0]) != 'e' || tolower(argv[3][1]) != 'c' || tolower(argv[3][2]) != 'b')
        {cout << "\nInvalid <mode> argument; Only ECB mode supported\n"; return 0;}
    ecbMode = true;
    #ifdef DEBUG
    cout << "\tbool ecbMode = ";
    if(ecbMode) cout << "TRUE" << endl;
    else cout << "FALSE" << endl;
    #endif

    // check if infile == outfile
    if(!strcmp(argv[4], argv[5])) {cout << "\nError: <infile> cannot be the same as <outfile>"; return 0;}

    // <infile>
    // attempt to open the input file as binary input stream
    infile.open(argv[4], fstream::in | fstream::binary);
    if(infile.fail()) {cout << "\nFailed to open \"" << argv[4] << "\"" << endl; return 0;}
    #ifdef DEBUG
    cout << "\nFile Access:\n\tSuccessfully opened  \"" << argv[4] << "\"" << endl;
    #endif

    // <outfile>
    outfile.open(argv[5], fstream::in);
    // check if file already exists; ask to overwrite if so
    if(outfile.good()) {
        outfile.close();
        cout << "\n\t\"" << argv[5] << "\" already exists.\n\tOverwrite? [y/n]:";
        char overwrite;
        cin >> overwrite;
        if(tolower(overwrite) == 'n') {cout << "Exiting DES"; return 0;}
        else if(tolower(overwrite) != 'y') {cout << "Invalid input; Exiting DES"; return 0;}
        // if overwrite allowed, open output file as truncated binary output stream
        // trunc discards any contents that existed in file
        outfile.open(argv[5], fstream::out | fstream::binary | fstream::trunc);
        if(outfile.fail()) {cout << "\nFailed to open \"" << argv[5] << "\"" << endl; return 0;}
        #ifdef DEBUG
        cout << "\tSuccessfully opened  \"" << argv[5] << "\"" << endl;
        #endif
    }
    else if(outfile.fail()){
        // if output file does not exist, create output file and open as binary output stream
        outfile.open(argv[5], fstream::out | fstream::binary);
        if(outfile.fail()) {cout << "\nFailed to create \"" << argv[5] << "\"" << endl; return 0;}
        #ifdef DEBUG
        cout << "\tSuccessfully created \"" << argv[5] << "\"" << endl;
        #endif
    }

    // Get the input file's size in bytes
    infile.seekg(0, infile.end); // put cursor at end of file to count its byte length
    // if file larger than 2 billion (and change) bytes
    if (infile.tellg() > 0x7fffffff) {
        cout << endl << argv[4] << " file size too large.";
        cout << "\nMust be between 0 and 2,147,483,647 bytes long. Exiting DES";
        return 0;
    }
    infile_byte_length = (uint64_t) infile.tellg(); // save file size in bytes
    bytes_remaining = (unsigned int)infile.tellg();
    infile.seekg(0, infile.beg); // put cursor at beginning of file



    // ------------------------------------------------------------------------
    // Generate sixteen 48 bit round keys (for each of DES's sixteen rounds)
    // from the given 64 bit key and store them in roundkey[]
    // ------------------------------------------------------------------------

    #ifdef DEBUG
    cout << "\nGenerating sixteen 48 bit round keys:";
    #endif

    // Compress 64 bit key to 56 bit permuted key ---------------/
    uint64_t compressed_56_bit_key = 0ULL;

    if(key & (1ULL << 63)) compressed_56_bit_key |= (1ULL << (56 - 8));
    if(key & (1ULL << 62)) compressed_56_bit_key |= (1ULL << (56 - 16));
    if(key & (1ULL << 61)) compressed_56_bit_key |= (1ULL << (56 - 24));
    if(key & (1ULL << 60)) compressed_56_bit_key |= (1ULL << (56 - 56));
    if(key & (1ULL << 59)) compressed_56_bit_key |= (1ULL << (56 - 52));
    if(key & (1ULL << 58)) compressed_56_bit_key |= (1ULL << (56 - 44));
    if(key & (1ULL << 57)) compressed_56_bit_key |= (1ULL << (56 - 36));

    if(key & (1ULL << 55)) compressed_56_bit_key |= (1ULL << (56 - 7));
    if(key & (1ULL << 54)) compressed_56_bit_key |= (1ULL << (56 - 15));
    if(key & (1ULL << 53)) compressed_56_bit_key |= (1ULL << (56 - 23));
    if(key & (1ULL << 52)) compressed_56_bit_key |= (1ULL << (56 - 55));
    if(key & (1ULL << 51)) compressed_56_bit_key |= (1ULL << (56 - 51));
    if(key & (1ULL << 50)) compressed_56_bit_key |= (1ULL << (56 - 43));
    if(key & (1ULL << 49)) compressed_56_bit_key |= (1ULL << (56 - 35));

    if(key & (1ULL << 47)) compressed_56_bit_key |= (1ULL << (56 - 6));
    if(key & (1ULL << 46)) compressed_56_bit_key |= (1ULL << (56 - 14));
    if(key & (1ULL << 45)) compressed_56_bit_key |= (1ULL << (56 - 22));
    if(key & (1ULL << 44)) compressed_56_bit_key |= (1ULL << (56 - 54));
    if(key & (1ULL << 43)) compressed_56_bit_key |= (1ULL << (56 - 50));
    if(key & (1ULL << 42)) compressed_56_bit_key |= (1ULL << (56 - 42));
    if(key & (1ULL << 41)) compressed_56_bit_key |= (1ULL << (56 - 34));

    if(key & (1ULL << 39)) compressed_56_bit_key |= (1ULL << (56 - 5));
    if(key & (1ULL << 38)) compressed_56_bit_key |= (1ULL << (56 - 13));
    if(key & (1ULL << 37)) compressed_56_bit_key |= (1ULL << (56 - 21));
    if(key & (1ULL << 36)) compressed_56_bit_key |= (1ULL << (56 - 53));
    if(key & (1ULL << 35)) compressed_56_bit_key |= (1ULL << (56 - 49));
    if(key & (1ULL << 34)) compressed_56_bit_key |= (1ULL << (56 - 41));
    if(key & (1ULL << 33)) compressed_56_bit_key |= (1ULL << (56 - 33));

    if(key & (1ULL << 31)) compressed_56_bit_key |= (1ULL << (56 - 4));
    if(key & (1ULL << 30)) compressed_56_bit_key |= (1ULL << (56 - 12));
    if(key & (1ULL << 29)) compressed_56_bit_key |= (1ULL << (56 - 20));
    if(key & (1ULL << 28)) compressed_56_bit_key |= (1ULL << (56 - 28));
    if(key & (1ULL << 27)) compressed_56_bit_key |= (1ULL << (56 - 48));
    if(key & (1ULL << 26)) compressed_56_bit_key |= (1ULL << (56 - 40));
    if(key & (1ULL << 25)) compressed_56_bit_key |= (1ULL << (56 - 32));

    if(key & (1ULL << 23)) compressed_56_bit_key |= (1ULL << (56 - 3));
    if(key & (1ULL << 22)) compressed_56_bit_key |= (1ULL << (56 - 11));
    if(key & (1ULL << 21)) compressed_56_bit_key |= (1ULL << (56 - 19));
    if(key & (1ULL << 20)) compressed_56_bit_key |= (1ULL << (56 - 27));
    if(key & (1ULL << 19)) compressed_56_bit_key |= (1ULL << (56 - 47));
    if(key & (1ULL << 18)) compressed_56_bit_key |= (1ULL << (56 - 39));
    if(key & (1ULL << 17)) compressed_56_bit_key |= (1ULL << (56 - 31));

    if(key & (1ULL << 15)) compressed_56_bit_key |= (1ULL << (56 - 2));
    if(key & (1ULL << 14)) compressed_56_bit_key |= (1ULL << (56 - 10));
    if(key & (1ULL << 13)) compressed_56_bit_key |= (1ULL << (56 - 18));
    if(key & (1ULL << 12)) compressed_56_bit_key |= (1ULL << (56 - 26));
    if(key & (1ULL << 11)) compressed_56_bit_key |= (1ULL << (56 - 46));
    if(key & (1ULL << 10)) compressed_56_bit_key |= (1ULL << (56 - 38));
    if(key & (1ULL << 9)) compressed_56_bit_key |= (1ULL << (56 - 30));

    if(key & (1ULL << 7)) compressed_56_bit_key |= (1ULL << (56 - 1));
    if(key & (1ULL << 6)) compressed_56_bit_key |= (1ULL << (56 - 9));
    if(key & (1ULL << 5)) compressed_56_bit_key |= (1ULL << (56 - 17));
    if(key & (1ULL << 4)) compressed_56_bit_key |= (1ULL << (56 - 25));
    if(key & (1ULL << 3)) compressed_56_bit_key |= (1ULL << (56 - 45));
    if(key & (1ULL << 2)) compressed_56_bit_key |= (1ULL << (56 - 37));
    if(key & (1ULL << 1)) compressed_56_bit_key |= (1ULL << (56 - 29));

    #ifdef DEBUG
    cout << "\n\tcompressed_56_bit_key = ";
    print64(compressed_56_bit_key, 'b');
    cout << "\n\t                      = ";
    print64(compressed_56_bit_key, 'x');
    cout << endl;
    #endif

    // Compute the sixteen 48 bit round keys -----------------------------------/
    uint32_t left;
    uint32_t right;
    uint64_t compressed_48_bit_key;

    for(int i = 0; i < 16; ++i){
        // split compressed 56 bit key in half
        left  = (uint32_t)(compressed_56_bit_key >> 28);
        right = (uint32_t)(compressed_56_bit_key & 0x0000000FFFFFFF);

        if(i == 0 || i == 1 || i == 8 || i == 15){
            // rotate left (circular shift) by 1 bit
            left = ((left << 1) | (left >> 27)) & 0x0fffffff;
            right = ((right << 1) | (right >> 27)) & 0x0fffffff;
        }
        else {
            // rotate left (circular shift) by 2 bits
            left = ((left << 1) | (left >> 27)) & 0x0fffffff;
            left = ((left << 1) | (left >> 27)) & 0x0fffffff;
            right = ((right << 1) | (right >> 27)) & 0x0fffffff;
            right = ((right << 1) | (right >> 27)) & 0x0fffffff;
        }

        // combine both rotated 28 bit halves
        compressed_56_bit_key = (((uint64_t)left) << 28) | ((uint64_t)right);

        compressed_48_bit_key = 0ULL;

        // Compression permutation from 56 bit key to 48 bit key
        if(compressed_56_bit_key & (1ULL << 55)) compressed_48_bit_key |= (1ULL << (48 - 5));
        if(compressed_56_bit_key & (1ULL << 54)) compressed_48_bit_key |= (1ULL << (48 - 24));
        if(compressed_56_bit_key & (1ULL << 53)) compressed_48_bit_key |= (1ULL << (48 - 7));
        if(compressed_56_bit_key & (1ULL << 52)) compressed_48_bit_key |= (1ULL << (48 - 16));
        if(compressed_56_bit_key & (1ULL << 51)) compressed_48_bit_key |= (1ULL << (48 - 6));
        if(compressed_56_bit_key & (1ULL << 50)) compressed_48_bit_key |= (1ULL << (48 - 10));
        if(compressed_56_bit_key & (1ULL << 49)) compressed_48_bit_key |= (1ULL << (48 - 20));
        if(compressed_56_bit_key & (1ULL << 48)) compressed_48_bit_key |= (1ULL << (48 - 18));

        if(compressed_56_bit_key & (1ULL << 46)) compressed_48_bit_key |= (1ULL << (48 - 12));
        if(compressed_56_bit_key & (1ULL << 45)) compressed_48_bit_key |= (1ULL << (48 - 3));
        if(compressed_56_bit_key & (1ULL << 44)) compressed_48_bit_key |= (1ULL << (48 - 15));
        if(compressed_56_bit_key & (1ULL << 43)) compressed_48_bit_key |= (1ULL << (48 - 23));
        if(compressed_56_bit_key & (1ULL << 42)) compressed_48_bit_key |= (1ULL << (48 - 1));
        if(compressed_56_bit_key & (1ULL << 41)) compressed_48_bit_key |= (1ULL << (48 - 9));
        if(compressed_56_bit_key & (1ULL << 40)) compressed_48_bit_key |= (1ULL << (48 - 19));
        if(compressed_56_bit_key & (1ULL << 39)) compressed_48_bit_key |= (1ULL << (48 - 2));

        if(compressed_56_bit_key & (1ULL << 37)) compressed_48_bit_key |= (1ULL << (48 - 14));
        if(compressed_56_bit_key & (1ULL << 36)) compressed_48_bit_key |= (1ULL << (48 - 22));
        if(compressed_56_bit_key & (1ULL << 35)) compressed_48_bit_key |= (1ULL << (48 - 11));

        if(compressed_56_bit_key & (1ULL << 33)) compressed_48_bit_key |= (1ULL << (48 - 13));
        if(compressed_56_bit_key & (1ULL << 32)) compressed_48_bit_key |= (1ULL << (48 - 4));

        if(compressed_56_bit_key & (1ULL << 30)) compressed_48_bit_key |= (1ULL << (48 - 17));
        if(compressed_56_bit_key & (1ULL << 29)) compressed_48_bit_key |= (1ULL << (48 - 21));
        if(compressed_56_bit_key & (1ULL << 28)) compressed_48_bit_key |= (1ULL << (48 - 8));
        if(compressed_56_bit_key & (1ULL << 27)) compressed_48_bit_key |= (1ULL << (48 - 47));
        if(compressed_56_bit_key & (1ULL << 26)) compressed_48_bit_key |= (1ULL << (48 - 31));
        if(compressed_56_bit_key & (1ULL << 25)) compressed_48_bit_key |= (1ULL << (48 - 27));
        if(compressed_56_bit_key & (1ULL << 24)) compressed_48_bit_key |= (1ULL << (48 - 48));
        if(compressed_56_bit_key & (1ULL << 23)) compressed_48_bit_key |= (1ULL << (48 - 35));
        if(compressed_56_bit_key & (1ULL << 22)) compressed_48_bit_key |= (1ULL << (48 - 41));

        if(compressed_56_bit_key & (1ULL << 20)) compressed_48_bit_key |= (1ULL << (48 - 46));
        if(compressed_56_bit_key & (1ULL << 19)) compressed_48_bit_key |= (1ULL << (48 - 28));

        if(compressed_56_bit_key & (1ULL << 17)) compressed_48_bit_key |= (1ULL << (48 - 39));
        if(compressed_56_bit_key & (1ULL << 16)) compressed_48_bit_key |= (1ULL << (48 - 32));
        if(compressed_56_bit_key & (1ULL << 15)) compressed_48_bit_key |= (1ULL << (48 - 25));
        if(compressed_56_bit_key & (1ULL << 14)) compressed_48_bit_key |= (1ULL << (48 - 44));

        if(compressed_56_bit_key & (1ULL << 12)) compressed_48_bit_key |= (1ULL << (48 - 37));
        if(compressed_56_bit_key & (1ULL << 11)) compressed_48_bit_key |= (1ULL << (48 - 44));
        if(compressed_56_bit_key & (1ULL << 10)) compressed_48_bit_key |= (1ULL << (48 - 43));
        if(compressed_56_bit_key & (1ULL << 9)) compressed_48_bit_key |= (1ULL << (48 - 29));
        if(compressed_56_bit_key & (1ULL << 8)) compressed_48_bit_key |= (1ULL << (48 - 36));
        if(compressed_56_bit_key & (1ULL << 7)) compressed_48_bit_key |= (1ULL << (48 - 38));
        if(compressed_56_bit_key & (1ULL << 6)) compressed_48_bit_key |= (1ULL << (48 - 45));
        if(compressed_56_bit_key & (1ULL << 5)) compressed_48_bit_key |= (1ULL << (48 - 33));
        if(compressed_56_bit_key & (1ULL << 4)) compressed_48_bit_key |= (1ULL << (48 - 26));
        if(compressed_56_bit_key & (1ULL << 3)) compressed_48_bit_key |= (1ULL << (48 - 42));

        if(compressed_56_bit_key & (1ULL << 1)) compressed_48_bit_key |= (1ULL << (48 - 30));
        if(compressed_56_bit_key & (1ULL << 0)) compressed_48_bit_key |= (1ULL << (48 - 40));

        // save key
        roundkey[i] = compressed_48_bit_key;

        #ifdef DEBUG
        cout << "\troundkey[" << i << "] = ";
        print64(compressed_48_bit_key, 'b');
        cout << " = ";
        print64(compressed_48_bit_key, 'x');
        cout << endl;
        #endif
    }


    // ------------------------------------------------------------------------
    // Encrypt or Decrypt?
    // ------------------------------------------------------------------------

    if(encrypt) {
        #ifdef DEBUG
        cout << "\nEncryption:";
        #endif

        // Create first 64 bit block with file size
        // left 33 bits  = randomly generated garbage
        // right 31 bits = file size (in bytes)
        srand((unsigned int) time(NULL)); // set random seed to value determined by time
        // RAND_MAX is library-dependent; guaranteed to be at least 0x7FFF
        if (RAND_MAX < 0x1ffffffff) {

            // determine how many bits are in this library's RAND_MAX value
            // (assuming all bits of all RAND_MAX implementations are set (i.e. 0x7FFF, 0x7fffffff))
            // if RAND_MAX cannot generate large enough number, we need to generate 2 (or 3) random numbers and shift
            // some to fill in the empty space in our 33 bits of random space. All random numbers (after shifting)
            // will be XORed into the same 64 bit container.
            //
            // log2(x) gives us the binary bit location of the most significant bit in x minus 1 plus extra decimals
            // casting as int removes unwanted decimal places rounded down
            // playing nice and giving credit where credit is due: http://stackoverflow.com/a/29389014
            int shiftby = (((int) log2(0x1ffffffff)) + 1) - (((int) log2(RAND_MAX)) + 1);

            uint64_t rand33; // container for our randomly generated 33 bit value
            uint64_t rand1 = (uint64_t) (rand()) << shiftby;
            //srand((unsigned int)time(NULL)); // setting the random seed again doesn't make random as random
            uint64_t rand2 = (uint64_t) (rand());
            if (RAND_MAX < 0x1ffff) {
                //srand((unsigned int)time(NULL)); // setting the random seed again doesn't make random as random
                uint64_t rand3 = (uint64_t) (rand()) << (shiftby >> 1);
                rand33 = (rand1 ^ rand2 ^ rand3) << 31;
            }
            else rand33 = (rand1 ^ rand2) << 31; // xor random values into same 64 bit block and shift the value to
                                                 // be atthe left most position in the 64 bit block

            block = rand33 | infile_byte_length; // merge both the 33 random bits and the file size
                                                 // into same 64 bit block
        }
        else {
            // if rand() can generate a large enough value,
            // generate 2 values between 0 and 0x1ffffffff (33 bits all set)
            uint64_t rand1 = (uint64_t) (rand() % 0x1ffffffff);
            //srand((unsigned int)time(NULL)); // setting the random seed again doesn't make random as random
            uint64_t rand2 = (uint64_t) (rand() % 0x1ffffffff);
            uint64_t rand = (rand1 ^ rand2) << 31;  // xor random values into same 64 bit block and shift the
                                                    // value to be at the left most position in the 64 bit block

            block = rand | infile_byte_length;  // merge both the 33 random bits and the file size
                                                // into same 64 bit block
        }
        #ifdef DEBUG
        cout << "\n\tGenerated 64 bit block with left 33 bits as random and right 31 bits as file size in bytes" << endl;
        cout << "\t\t<infile> size = 0d" << infile_byte_length << " bytes";
        printf("\n\t\t              = 0x%llX bytes", infile_byte_length);
        cout << "\n\t\tfile size block = ";
        print64(block, 'b');
        cout << "\n\t\t                = ";
        print64(block, 'x');
        cout << endl;
        #endif

        cout << "\nEncrypting..." << endl;

        // TODO encrypt block
        DES();

        // write encrypted block (containing 33 bits of garbage and 31 bits of file length) to <outfile>
        writeBlock();

        while(bytes_remaining){
            readBlock();
            // TODO encrypt block
            DES();
            writeBlock();
        }
    }
    else{
        #ifdef DEBUG
        cout << "\nDecryption:";
        #endif

        if(infile_byte_length < 8) {cout << "\nInput file size too small. Exiting DES."; return 0;}
        if(infile_byte_length % 8) {cout << "\nInput file size not multiple of 8. Exiting DES."; return 0;}

        cout << "\nDecrypting block 0 of " << (infile_byte_length >> 3);
        unsigned int currentBlock = 0;

        // read first block containing original file length
        readBlock();

        // comment
        // TODO decrypt block

        // extract file length value by bit masking
        bytes_remaining = (unsigned int)(block & 0x000000007fffffff);

        // read, decrypt, and write until no more bytes left
        while(bytes_remaining){
            readBlock();
            ++currentBlock;
            cout << "\rDecrypting block " << currentBlock << " of " << (infile_byte_length >> 3);
            // TODO decrypt block
            writeBlock();
        }
    }

    // TODO print out time statistics

    cout << "\nDone." << endl;

    return 0;
}

// Data Encryption Standard
// Here, we'll run the 64 bit block through the DES algorithm
// 1) run block through initial permutation
// 2) run block through the 16 rounds
//      2.1)
//      2.2)
//      2.3)
// TODO check if we have to swap after 16th round
// 3) run block through final permutation
void DES(){

    // ------------------------------------------------------------------------
    // Initial Permutation
    // ------------------------------------------------------------------------

    uint64_t initial_permutation = 0ULL;

    //6666655555555554444444444333333333322222222221111111111
    //4321098765432109876543210987654321098765432109876543210987654321
    //0000000000000000000000001000000000000000000000000000000000000000
    //666655555555554444444444333333333322222222221111111111
    //3210987654321098765432109876543210987654321098765432109876543210

    if(block & (1ULL << 63)) initial_permutation |= (1ULL << (64 - 40));
    if(block & (1ULL << 62)) initial_permutation |= (1ULL << (64 - 8));
    if(block & (1ULL << 61)) initial_permutation |= (1ULL << (64 - 48));
    if(block & (1ULL << 60)) initial_permutation |= (1ULL << (64 - 16));
    if(block & (1ULL << 59)) initial_permutation |= (1ULL << (64 - 56));
    if(block & (1ULL << 58)) initial_permutation |= (1ULL << (64 - 24));
    if(block & (1ULL << 57)) initial_permutation |= (1ULL << (64 - 64));
    if(block & (1ULL << 56)) initial_permutation |= (1ULL << (64 - 32));
    if(block & (1ULL << 55)) initial_permutation |= (1ULL << (64 - 39));
    if(block & (1ULL << 54)) initial_permutation |= (1ULL << (64 - 7));
    if(block & (1ULL << 53)) initial_permutation |= (1ULL << (64 - 47));
    if(block & (1ULL << 52)) initial_permutation |= (1ULL << (64 - 15));
    if(block & (1ULL << 51)) initial_permutation |= (1ULL << (64 - 55));
    if(block & (1ULL << 50)) initial_permutation |= (1ULL << (64 - 23));
    if(block & (1ULL << 49)) initial_permutation |= (1ULL << (64 - 63));
    if(block & (1ULL << 48)) initial_permutation |= (1ULL << (64 - 31));

    if(block & (1ULL << 47)) initial_permutation |= (1ULL << (64 - 38));
    if(block & (1ULL << 46)) initial_permutation |= (1ULL << (64 - 6));
    if(block & (1ULL << 45)) initial_permutation |= (1ULL << (64 - 46));
    if(block & (1ULL << 44)) initial_permutation |= (1ULL << (64 - 14));
    if(block & (1ULL << 43)) initial_permutation |= (1ULL << (64 - 54));
    if(block & (1ULL << 42)) initial_permutation |= (1ULL << (64 - 22));
    if(block & (1ULL << 41)) initial_permutation |= (1ULL << (64 - 62));
    if(block & (1ULL << 40)) initial_permutation |= (1ULL << (64 - 30));
    if(block & (1ULL << 39)) initial_permutation |= (1ULL << (64 - 37));
    if(block & (1ULL << 38)) initial_permutation |= (1ULL << (64 - 5));
    if(block & (1ULL << 37)) initial_permutation |= (1ULL << (64 - 45));
    if(block & (1ULL << 36)) initial_permutation |= (1ULL << (64 - 13));
    if(block & (1ULL << 35)) initial_permutation |= (1ULL << (64 - 53));
    if(block & (1ULL << 34)) initial_permutation |= (1ULL << (64 - 21));
    if(block & (1ULL << 33)) initial_permutation |= (1ULL << (64 - 61));
    if(block & (1ULL << 32)) initial_permutation |= (1ULL << (64 - 29));

    if(block & (1ULL << 31)) initial_permutation |= (1ULL << (64 - 36));
    if(block & (1ULL << 30)) initial_permutation |= (1ULL << (64 - 4));
    if(block & (1ULL << 29)) initial_permutation |= (1ULL << (64 - 44));
    if(block & (1ULL << 28)) initial_permutation |= (1ULL << (64 - 12));
    if(block & (1ULL << 27)) initial_permutation |= (1ULL << (64 - 52));
    if(block & (1ULL << 26)) initial_permutation |= (1ULL << (64 - 20));
    if(block & (1ULL << 25)) initial_permutation |= (1ULL << (64 - 60));
    if(block & (1ULL << 24)) initial_permutation |= (1ULL << (64 - 28));
    if(block & (1ULL << 23)) initial_permutation |= (1ULL << (64 - 35));
    if(block & (1ULL << 22)) initial_permutation |= (1ULL << (64 - 3));
    if(block & (1ULL << 21)) initial_permutation |= (1ULL << (64 - 43));
    if(block & (1ULL << 20)) initial_permutation |= (1ULL << (64 - 11));
    if(block & (1ULL << 19)) initial_permutation |= (1ULL << (64 - 51));
    if(block & (1ULL << 18)) initial_permutation |= (1ULL << (64 - 19));
    if(block & (1ULL << 17)) initial_permutation |= (1ULL << (64 - 59));
    if(block & (1ULL << 16)) initial_permutation |= (1ULL << (64 - 27));

    if(block & (1ULL << 15)) initial_permutation |= (1ULL << (64 - 34));
    if(block & (1ULL << 14)) initial_permutation |= (1ULL << (64 - 2));
    if(block & (1ULL << 13)) initial_permutation |= (1ULL << (64 - 42));
    if(block & (1ULL << 12)) initial_permutation |= (1ULL << (64 - 10));
    if(block & (1ULL << 11)) initial_permutation |= (1ULL << (64 - 50));
    if(block & (1ULL << 10)) initial_permutation |= (1ULL << (64 - 18));
    if(block & (1ULL << 9)) initial_permutation |= (1ULL << (64 - 58));
    if(block & (1ULL << 8)) initial_permutation |= (1ULL << (64 - 26));
    if(block & (1ULL << 7)) initial_permutation |= (1ULL << (64 - 33));
    if(block & (1ULL << 6)) initial_permutation |= (1ULL << (64 - 1));
    if(block & (1ULL << 5)) initial_permutation |= (1ULL << (64 - 41));
    if(block & (1ULL << 4)) initial_permutation |= (1ULL << (64 - 9));
    if(block & (1ULL << 3)) initial_permutation |= (1ULL << (64 - 49));
    if(block & (1ULL << 2)) initial_permutation |= (1ULL << (64 - 17));
    if(block & (1ULL << 1)) initial_permutation |= (1ULL << (64 - 57));
    if(block & (1ULL << 0)) initial_permutation |= (1ULL << (64 - 25));

    // ------------------------------------------------------------------------
    // TODO 16 Rounds
    // ------------------------------------------------------------------------

    // Split 64 bit input into left and right 32 bit halves
    uint32_t left32  = (uint32_t)(initial_permutation >> 32);
    uint32_t right32 = (uint32_t)(initial_permutation & 0x00000000ffffffff);

    // Expand 32 bit right half into 48 bit permuted right half
    uint64_t right48 = 0ULL;
    if(right32 & (1ULL << 31)) {right48 |= (1ULL << (48 - 2)); right48 |= (1ULL << (48 - 48));}
    if(right32 & (1ULL << 30))  right48 |= (1ULL << (48 - 3));
    if(right32 & (1ULL << 29))  right48 |= (1ULL << (48 - 4));
    if(right32 & (1ULL << 28)) {right48 |= (1ULL << (48 - 5)); right48 |= (1ULL << (48 - 7));}
    if(right32 & (1ULL << 27)) {right48 |= (1ULL << (48 - 6)); right48 |= (1ULL << (48 - 8));}
    if(right32 & (1ULL << 26))  right48 |= (1ULL << (48 - 9));
    if(right32 & (1ULL << 25))  right48 |= (1ULL << (48 - 10));
    if(right32 & (1ULL << 24)) {right48 |= (1ULL << (48 - 11)); right48 |= (1ULL << (48 - 13));}
    if(right32 & (1ULL << 23)) {right48 |= (1ULL << (48 - 12)); right48 |= (1ULL << (48 - 14));}
    if(right32 & (1ULL << 22))  right48 |= (1ULL << (48 - 15));
    if(right32 & (1ULL << 21))  right48 |= (1ULL << (48 - 16));
    if(right32 & (1ULL << 20)) {right48 |= (1ULL << (48 - 17)); right48 |= (1ULL << (48 - 19));}
    if(right32 & (1ULL << 19)) {right48 |= (1ULL << (48 - 18)); right48 |= (1ULL << (48 - 20));}
    if(right32 & (1ULL << 18))  right48 |= (1ULL << (48 - 21));
    if(right32 & (1ULL << 17))  right48 |= (1ULL << (48 - 22));
    if(right32 & (1ULL << 16)) {right48 |= (1ULL << (48 - 23)); right48 |= (1ULL << (48 - 25));}
    if(right32 & (1ULL << 15)) {right48 |= (1ULL << (48 - 24)); right48 |= (1ULL << (48 - 26));}
    if(right32 & (1ULL << 14))  right48 |= (1ULL << (48 - 27));
    if(right32 & (1ULL << 13))  right48 |= (1ULL << (48 - 28));
    if(right32 & (1ULL << 12)) {right48 |= (1ULL << (48 - 29)); right48 |= (1ULL << (48 - 31));}
    if(right32 & (1ULL << 11)) {right48 |= (1ULL << (48 - 30)); right48 |= (1ULL << (48 - 32));}
    if(right32 & (1ULL << 10))  right48 |= (1ULL << (48 - 33));
    if(right32 & (1ULL << 9))  right48 |= (1ULL << (48 - 34));
    if(right32 & (1ULL << 8)) {right48 |= (1ULL << (48 - 35)); right48 |= (1ULL << (48 - 37));}
    if(right32 & (1ULL << 7)) {right48 |= (1ULL << (48 - 36)); right48 |= (1ULL << (48 - 38));}
    if(right32 & (1ULL << 6))  right48 |= (1ULL << (48 - 39));
    if(right32 & (1ULL << 5))  right48 |= (1ULL << (48 - 40));
    if(right32 & (1ULL << 4)) {right48 |= (1ULL << (48 - 41)); right48 |= (1ULL << (48 - 43));}
    if(right32 & (1ULL << 3)) {right48 |= (1ULL << (48 - 42)); right48 |= (1ULL << (48 - 44));}
    if(right32 & (1ULL << 2))  right48 |= (1ULL << (48 - 45));
    if(right32 & (1ULL << 1))  right48 |= (1ULL << (48 - 46));
    if(right32 & (1ULL << 0)) {right48 |= (1ULL << (48 - 47)); right48 |= (1ULL << (48 - 1));}






    // ------------------------------------------------------------------------
    // Final Permutation
    // ------------------------------------------------------------------------

    uint64_t final_permutation = 0ULL;

    uint64_t temp = initial_permutation;

    if(temp & (1ULL << 63)) final_permutation |= (1ULL << (64 - 58));
    if(temp & (1ULL << 62)) final_permutation |= (1ULL << (64 - 50));
    if(temp & (1ULL << 61)) final_permutation |= (1ULL << (64 - 42));
    if(temp & (1ULL << 60)) final_permutation |= (1ULL << (64 - 34));
    if(temp & (1ULL << 59)) final_permutation |= (1ULL << (64 - 26));
    if(temp & (1ULL << 58)) final_permutation |= (1ULL << (64 - 18));
    if(temp & (1ULL << 57)) final_permutation |= (1ULL << (64 - 10));
    if(temp & (1ULL << 56)) final_permutation |= (1ULL << (64 - 2));
    if(temp & (1ULL << 55)) final_permutation |= (1ULL << (64 - 60));
    if(temp & (1ULL << 54)) final_permutation |= (1ULL << (64 - 52));
    if(temp & (1ULL << 53)) final_permutation |= (1ULL << (64 - 44));
    if(temp & (1ULL << 52)) final_permutation |= (1ULL << (64 - 36));
    if(temp & (1ULL << 51)) final_permutation |= (1ULL << (64 - 28));
    if(temp & (1ULL << 50)) final_permutation |= (1ULL << (64 - 20));
    if(temp & (1ULL << 49)) final_permutation |= (1ULL << (64 - 12));
    if(temp & (1ULL << 48)) final_permutation |= (1ULL << (64 - 4));

    if(temp & (1ULL << 47)) final_permutation |= (1ULL << (64 - 62));
    if(temp & (1ULL << 46)) final_permutation |= (1ULL << (64 - 54));
    if(temp & (1ULL << 45)) final_permutation |= (1ULL << (64 - 46));
    if(temp & (1ULL << 44)) final_permutation |= (1ULL << (64 - 38));
    if(temp & (1ULL << 43)) final_permutation |= (1ULL << (64 - 30));
    if(temp & (1ULL << 42)) final_permutation |= (1ULL << (64 - 22));
    if(temp & (1ULL << 41)) final_permutation |= (1ULL << (64 - 14));
    if(temp & (1ULL << 40)) final_permutation |= (1ULL << (64 - 6));
    if(temp & (1ULL << 39)) final_permutation |= (1ULL << (64 - 64));
    if(temp & (1ULL << 38)) final_permutation |= (1ULL << (64 - 56));
    if(temp & (1ULL << 37)) final_permutation |= (1ULL << (64 - 48));
    if(temp & (1ULL << 36)) final_permutation |= (1ULL << (64 - 40));
    if(temp & (1ULL << 35)) final_permutation |= (1ULL << (64 - 32));
    if(temp & (1ULL << 34)) final_permutation |= (1ULL << (64 - 24));
    if(temp & (1ULL << 33)) final_permutation |= (1ULL << (64 - 16));
    if(temp & (1ULL << 32)) final_permutation |= (1ULL << (64 - 8));

    if(temp & (1ULL << 31)) final_permutation |= (1ULL << (64 - 57));
    if(temp & (1ULL << 30)) final_permutation |= (1ULL << (64 - 49));
    if(temp & (1ULL << 29)) final_permutation |= (1ULL << (64 - 41));
    if(temp & (1ULL << 28)) final_permutation |= (1ULL << (64 - 33));
    if(temp & (1ULL << 27)) final_permutation |= (1ULL << (64 - 25));
    if(temp & (1ULL << 26)) final_permutation |= (1ULL << (64 - 17));
    if(temp & (1ULL << 25)) final_permutation |= (1ULL << (64 - 9));
    if(temp & (1ULL << 24)) final_permutation |= (1ULL << (64 - 1));
    if(temp & (1ULL << 23)) final_permutation |= (1ULL << (64 - 59));
    if(temp & (1ULL << 22)) final_permutation |= (1ULL << (64 - 51));
    if(temp & (1ULL << 21)) final_permutation |= (1ULL << (64 - 43));
    if(temp & (1ULL << 20)) final_permutation |= (1ULL << (64 - 35));
    if(temp & (1ULL << 19)) final_permutation |= (1ULL << (64 - 27));
    if(temp & (1ULL << 18)) final_permutation |= (1ULL << (64 - 19));
    if(temp & (1ULL << 17)) final_permutation |= (1ULL << (64 - 11));
    if(temp & (1ULL << 16)) final_permutation |= (1ULL << (64 - 3));

    if(temp & (1ULL << 15)) final_permutation |= (1ULL << (64 - 61));
    if(temp & (1ULL << 14)) final_permutation |= (1ULL << (64 - 53));
    if(temp & (1ULL << 13)) final_permutation |= (1ULL << (64 - 45));
    if(temp & (1ULL << 12)) final_permutation |= (1ULL << (64 - 37));
    if(temp & (1ULL << 11)) final_permutation |= (1ULL << (64 - 29));
    if(temp & (1ULL << 10)) final_permutation |= (1ULL << (64 - 21));
    if(temp & (1ULL << 9)) final_permutation |= (1ULL << (64 - 13));
    if(temp & (1ULL << 8)) final_permutation |= (1ULL << (64 - 5));
    if(temp & (1ULL << 7)) final_permutation |= (1ULL << (64 - 63));
    if(temp & (1ULL << 6)) final_permutation |= (1ULL << (64 - 55));
    if(temp & (1ULL << 5)) final_permutation |= (1ULL << (64 - 47));
    if(temp & (1ULL << 4)) final_permutation |= (1ULL << (64 - 39));
    if(temp & (1ULL << 3)) final_permutation |= (1ULL << (64 - 31));
    if(temp & (1ULL << 2)) final_permutation |= (1ULL << (64 - 23));
    if(temp & (1ULL << 1)) final_permutation |= (1ULL << (64 - 15));
    if(temp & (1ULL << 0)) final_permutation |= (1ULL << (64 - 7));



    if(final_permutation != block) {cout << "\nFinal permutation != block."; exit(0);}
    block = final_permutation;

    // ------------------------------------------------------------------------
    // TODO
    // ------------------------------------------------------------------------


    return;
}


// read 8 bytes from <infile> and places them in the global block variable
// if 8 bytes not available, read as many bytes as possible and fill in the rest with random chars
void readBlock(){
    if(!infile.is_open()) {cout << "\nError while reading from <infile>. File not open. Exiting DES."; exit(0);}

    block = 0ULL;

    char buffer[8]; // storage for all 8 chars in 64 bits
    infile.read(buffer, 8); // read 8 bytes from infile and store them in buffer[]

    // if read() reaches end of file, it sets both eof and failbit flags
    if(infile.fail() && !infile.eof()) {cout << "\nError while reading from <infile>. Exiting DES."; exit(0);}

    // if end of file reached, fill the remaining bytes in buffer[] with random garbage
    if(infile.eof()) for(int i = (int)infile.gcount(); i < 8; ++i) buffer[i] = (unsigned char)(rand() % 256);

    if(encrypt) bytes_remaining -= infile.gcount();

    // place contents of buffer[] into appropriate location in 64 bit block;
    // have to cast buffer as unsigned char before casting as uint64_t or else
    // sign carries over and fills block with bunch of 1s
    block |= (uint64_t)((unsigned char)buffer[0]) << 56;
    block |= (uint64_t)((unsigned char)buffer[1]) << 48;
    block |= (uint64_t)((unsigned char)buffer[2]) << 40;
    block |= (uint64_t)((unsigned char)buffer[3]) << 32;
    block |= (uint64_t)((unsigned char)buffer[4]) << 24;
    block |= (uint64_t)((unsigned char)buffer[5]) << 16;
    block |= (uint64_t)((unsigned char)buffer[6]) << 8;
    block |= (uint64_t)((unsigned char)buffer[7]);

    //#define readBlock_DEBUG
    #ifdef readBlock_DEBUG
    cout << "\nreadBlock(){";
    // print each buffer element as char and hex value
    for(int i = 0; i < 8; ++i) {
        cout << "\n\tbuffer[" << i << "] = '" << (unsigned char)buffer[i] << "' = ";
        printf("0x%02X", (unsigned char)buffer[i]); // %02X prints 2 uppercase hex digits
    }
    // print block as hex and binary
    cout << "\n\tblock = ";
    print64(block, 'x');
    cout << "\n\t      = ";
    print64(block, 'b');
    cout << "\n}" << endl;
    #endif

    return;
}


// write 64 bit block to <outfile> or
// n bytes if writing last decrypted block containing padding garbage bytes
void writeBlock(){
    if(!outfile.is_open()) {cout << "\nError while writing to <outfile>. File not open. Exiting DES."; exit(0);}

    char buffer[8]; // storage for all 8 chars in 64 bits

    // grab byte chunks from 64 bit block and place them into buffer[]
    // first, bit mask the byte needed
    // then, shift the value so bits are in lower 8 bits of uint64_t
    // finally, as an optional step, cast as char so compiler/IDE doesn't complain
    buffer[0] = (char)((block & 0xff00000000000000) >> 56);
    buffer[1] = (char)((block & 0x00ff000000000000) >> 48);
    buffer[2] = (char)((block & 0x0000ff0000000000) >> 40);
    buffer[3] = (char)((block & 0x000000ff00000000) >> 32);
    buffer[4] = (char)((block & 0x00000000ff000000) >> 24);
    buffer[5] = (char)((block & 0x0000000000ff0000) >> 16);
    buffer[6] = (char)((block & 0x000000000000ff00) >> 8);
    buffer[7] = (char)((block & 0x00000000000000ff));

    // if we're encrypting, don't subtract from bytes_remaining
    if(encrypt) outfile.write(buffer, 8);
    else{
        // write buffer to <outfile>
        if(bytes_remaining < 8) {outfile.write(buffer, bytes_remaining); bytes_remaining -= bytes_remaining;}
        else {outfile.write(buffer, 8); bytes_remaining -= 8;}
    }

    // force ofstream buffer to write to file now
    outfile.flush();

    // check for any errors from writing to file
    if(outfile.fail()) {cout << "\nError while writing to <outfile>. Exiting DES."; exit(0);}

    //#define writeBlock_DEBUG
    #ifdef writeBlock_DEBUG
    cout << "\nwriteBlock(){";
    // print each buffer element as char and hex value
    for(int i = 0; i < 8; ++i) {
        cout << "\n\tbuffer[" << i << "] = '" << (unsigned char)buffer[i] << "' = ";
        printf("0x%02X", (unsigned char)buffer[i]); // %02X prints 2 uppercase hex digits
        if((unsigned char)buffer[i] > 0xff) cout << "; buffer[" << i << "] = " << (unsigned char)buffer[i] << " too large!!!";
    }
    // print block as hex and binary
    cout << "\n\tblock = ";
    print64(block, 'x');
    cout << "\n\t      = ";
    print64(block, 'b');
    cout << "\n}" << endl;
    #endif

    return;
}


// cout the given 64 bit value in its binary, hex, or "string" representation
// char type defines cout as 'b' for binary, 'h' for hex, or 's' for string
void print64(uint64_t &value, char type){

    switch(tolower(type)){

        // print in binary form
        case 'b': {
            cout << "0b";
            // go through all 64 bits and print out "1" if bit set, "0" otherwise
            for (int i = 63; i >= 0; --i) {
                if (value & (1ULL << i)) cout << "1";
                else cout << "0";
            }
            break;
        }

        // print in hex form
        case 'x': {
            printf("0x%016llX", value); // '016' = print 16 characters (will include leading zeros)
                                        // 'll'  = treat value as 64 bit (long long)
                                        // 'X'   = print as uppercase HEX value
            break;
        }

        // print in ascii string form
        case 's':{
            char key_string[8] = {0, 0, 0, 0, 0, 0, 0, 0}; // storage for all 8 chars in 64 bits
            // go through all 64 bits and set appropriate bits in all 8 chars
            for(int i = 63, k = 0; i >=0; --i){
                // check if bit location i is set; if so, set the appropriate bit in key_string[k]
                if(key & (1ULL << i)) key_string[k] |= (1 << (i % 8));
                if(!(i % 8)) ++k;
            }
            cout << "\"";
            for(int i = 0; i < 8; ++i) cout << key_string[i]; // print out all 8 chars
            cout << "\"";
            break;
        }

        default:{
            cout << "\nUnknown type \'" << type << "\' as input parameter to print64(); Exiting DES\n";
            exit(0);
        }
    }

    return;
}