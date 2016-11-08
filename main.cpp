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

// comment out this define if not on POSIX system
//#define POSIX

#ifdef POSIX
#include <pthread.h>
#endif

// comment out this define to prevent debugging text from printing to the console
//#define VERBOSE_DEBUG

using namespace std;

bool encrypt;                   // encrypt (true) or decrypt (false)
uint64_t key;                   // 64 bit DES key (56 bits actually used)
bool ecbMode;                   // should always be true; only ecb mode supported
fstream infile;                 // input file stream
fstream outfile;                // output file stream
uint64_t block;                 // container for our 64 bit block throughout the DES algorithm
uint64_t infile_byte_length;
unsigned int bytes_remaining;   // number of bytes yet to be read
uint64_t roundkey[16];          // storage for the sixteen 48 bit sub keys used throughout DES's sixteen cycles
clock_t start_time;             // storage for start time

// DES algorightm specific vars.
// defined here to reduce compiler generated
// instructions within DES() to speed up algorithm
uint64_t DES_rounds_block;
uint64_t DES_left32;
uint64_t DES_right32;
uint64_t saved_right32;

//const int s1[] = {
//        14, 4,13, 1, 2,15,11, 8, 3,10, 6,12, 5, 9, 0, 7,
//         0,15, 7, 4,14, 2,13, 1,10, 6,12,11, 9, 5, 3, 8,
//         4, 1,14, 8,13, 6, 2,11,15,12, 9, 7, 3,10, 5, 0,
//        15,12, 8, 2, 4, 9, 1, 7, 5,11, 3,14,10, 0, 6,13};
//const int s2[] = {
//        15, 1, 8,14, 6,11, 3, 4, 9, 7, 2,13,12, 0, 5,10,
//         3,13, 4, 7,15, 2, 8,14,12, 0, 1,10, 6, 9,11, 5,
//         0,14, 7,11,10, 4,13, 1, 5, 8,12, 6, 9, 3, 2,15,
//        13, 8,10, 1, 3,15, 4, 2,11, 6, 7,12, 0, 5,14, 9};
//const int s3[] = {
//        10, 0, 9,14, 6, 3,15, 5, 1,13,12, 7,11, 4, 2, 8,
//        13, 7, 0, 9, 3, 4, 6,10, 2, 8, 5,14,12,11,15, 1,
//        13, 6, 4, 9, 8,15, 3, 0,11, 1, 2,12, 5,10,14, 7,
//         1,10,13, 0, 6, 9, 8, 7, 4,15,14, 3,11, 5, 2,12};
//const int s4[] = {
//         7,13,14, 3, 0, 6, 9,10, 1, 2, 8, 5,11,12, 4,15,
//        13, 8,11, 5, 6,15, 0, 3, 4, 7, 2,12, 1,10,14, 9,
//        10, 6, 9, 0,12,11, 7,13,15, 1, 3,14, 5, 2, 8, 4,
//         3,15, 0, 6,10, 1,13, 8, 9, 4, 5,11,12, 7, 2,14};
//const int s5[] = {
//         2,12, 4, 1, 7,10,11, 6, 8, 5, 3,15,13, 0,14, 9,
//        14,11, 2,12, 4, 7,13, 1, 5, 0,15,10, 3, 9, 8, 6,
//         4, 2, 1,11,10,13, 7, 8,15, 9,12, 5, 6, 3, 0,14,
//        11, 8,12, 7, 1,14, 2,13, 6,15, 0, 9,10, 4, 5, 3};
//const int s6[] = {
//        12, 1,10,15, 9, 2, 6, 8, 0,13, 3, 4,14, 7, 5,11,
//        10,15, 4, 2, 7,12, 9, 5, 6, 1,13,14, 0,11, 3, 8,
//         9,14,15, 5, 2, 8,12, 3, 7, 0, 4,10, 1,13,11, 6,
//         4, 3, 2,12, 9, 5,15,10,11,14, 1, 7, 6, 0, 8,13};
//const int s7[] = {
//         4,11, 2,14,15, 0, 8,13, 3,12, 9, 7, 5,10, 6, 1,
//        13, 0,11, 7, 4, 9, 1,10,14, 3, 5,12, 2,15, 8, 6,
//         1, 4,11,13,12, 3, 7,14,10,15, 6, 8, 0, 5, 9, 2,
//         6,11,13, 8, 1, 4,10, 7, 9, 5, 0,15,14, 2, 3,12};
//const int s8[] = {
//        13, 2, 8, 4, 6,15,11, 1,10, 9, 3,14, 5, 0,12, 7,
//         1,15,13, 8,10, 3, 7, 4,12, 5, 6,11, 0,14, 9, 2,
//         7,11, 4, 1, 9,12,14, 2, 0, 6,10,13,15, 3, 5, 8,
//         2, 1,14, 7, 4,10, 8,13,15,12, 9, 0, 3, 5, 6,11};
const int s1[4][16] = {
        {14, 4,13, 1, 2,15,11, 8, 3,10, 6,12, 5, 9, 0, 7},
        { 0,15, 7, 4,14, 2,13, 1,10, 6,12,11, 9, 5, 3, 8},
        { 4, 1,14, 8,13, 6, 2,11,15,12, 9, 7, 3,10, 5, 0},
        {15,12, 8, 2, 4, 9, 1, 7, 5,11, 3,14,10, 0, 6,13}
};
const int s2[4][16] = {
        {15, 1, 8,14, 6,11, 3, 4, 9, 7, 2,13,12, 0, 5,10},
        { 3,13, 4, 7,15, 2, 8,14,12, 0, 1,10, 6, 9,11, 5},
        { 0,14, 7,11,10, 4,13, 1, 5, 8,12, 6, 9, 3, 2,15},
        {13, 8,10, 1, 3,15, 4, 2,11, 6, 7,12, 0, 5,14, 9}
};
const int s3[4][16] = {
        {10, 0, 9,14, 6, 3,15, 5, 1,13,12, 7,11, 4, 2, 8},
        {13, 7, 0, 9, 3, 4, 6,10, 2, 8, 5,14,12,11,15, 1},
        {13, 6, 4, 9, 8,15, 3, 0,11, 1, 2,12, 5,10,14, 7},
        { 1,10,13, 0, 6, 9, 8, 7, 4,15,14, 3,11, 5, 2,12}
};
const int s4[4][16] = {
        { 7,13,14, 3, 0, 6, 9,10, 1, 2, 8, 5,11,12, 4,15},
        {13, 8,11, 5, 6,15, 0, 3, 4, 7, 2,12, 1,10,14, 9},
        {10, 6, 9, 0,12,11, 7,13,15, 1, 3,14, 5, 2, 8, 4},
        { 3,15, 0, 6,10, 1,13, 8, 9, 4, 5,11,12, 7, 2,14}
};
const int s5[4][16] = {
        { 2,12, 4, 1, 7,10,11, 6, 8, 5, 3,15,13, 0,14, 9},
        {14,11, 2,12, 4, 7,13, 1, 5, 0,15,10, 3, 9, 8, 6},
        { 4, 2, 1,11,10,13, 7, 8,15, 9,12, 5, 6, 3, 0,14},
        {11, 8,12, 7, 1,14, 2,13, 6,15, 0, 9,10, 4, 5, 3}
};
const int s6[4][16] = {
        {12, 1,10,15, 9, 2, 6, 8, 0,13, 3, 4,14, 7, 5,11},
        {10,15, 4, 2, 7,12, 9, 5, 6, 1,13,14, 0,11, 3, 8},
        { 9,14,15, 5, 2, 8,12, 3, 7, 0, 4,10, 1,13,11, 6},
        { 4, 3, 2,12, 9, 5,15,10,11,14, 1, 7, 6, 0, 8,13}
};
const int s7[4][16] = {
        { 4,11, 2,14,15, 0, 8,13, 3,12, 9, 7, 5,10, 6, 1},
        {13, 0,11, 7, 4, 9, 1,10,14, 3, 5,12, 2,15, 8, 6},
        { 1, 4,11,13,12, 3, 7,14,10,15, 6, 8, 0, 5, 9, 2},
        { 6,11,13, 8, 1, 4,10, 7, 9, 5, 0,15,14, 2, 3,12}
};
const int s8[4][16] = {
        {13, 2, 8, 4, 6,15,11, 1,10, 9, 3,14, 5, 0,12, 7},
        { 1,15,13, 8,10, 3, 7, 4,12, 5, 6,11, 0,14, 9, 2},
        { 7,11, 4, 1, 9,12,14, 2, 0, 6,10,13,15, 3, 5, 8},
        { 2, 1,14, 7, 4,10, 8,13,15,12, 9, 0, 3, 5, 6,11}
};

// function input/output defined with function definition
void print64(uint64_t &value, char type);
void readBlock();
void writeBlock();
void DES();

int main(int argc, char *argv[]) {

    start_time = clock();

    // Help argument; describe acceptable arguments
    if(argc == 1 || (argc == 2 && !strncmp(argv[1], "help", 4))) {
        cout << "\nDES Help - Acceptable Arguments";
        cout << "\n\n\t<-action> <key> <mode> <infile> <outfile>\n";
        cout << "\n\t\t<-action> -e to encrypt <infile> or -d to decrypt <infile>";
        cout << "\n\t\t<key> 8 character string surrounded by single quotes or 64 bit HEX value (without 0x prefix)";
        cout << "\n\t\t<mode> only ecb mode supported; argument should read \"ecb\" (without quotes)";
        cout << "\n\t\t<infile> input file to encrypt or decrypt";
        cout << "\n\t\t<outfile> output file to save encrypted or decrypted data" << endl;
        cout << "\nIf there are any $ (dollar signs) in your key, precede each with a \\ (backslash) to escape their "
             << "other functions. The dollar sign acts as a special shell variable that returns other data." << endl
             << endl;
        return 0;
    }

    // ------------------------------------------------------------------------
    // Validate and sanitize arguments
    // ------------------------------------------------------------------------
    if (argc != 6) {cout << "Invalid argument length!\n"; return 0;}

    #ifdef VERBOSE_DEBUG
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
        {cout << "\nInvalid <-action> argument! Only -e and -d allowed. For help, run DES with no arguments."
              << "\nYour <-action> = " << argv[1] << endl; return 0;}
    if(tolower(argv[1][1]) == 'e') encrypt = true;
    else if(tolower(argv[1][1]) != 'd')
        {cout << "\nInvalid <-action> argument! Only -e and -d allowed. For help, run DES with no arguments."
              << "\nYour <-action> = " << argv[1] << endl; return 0;}
    #ifdef VERBOSE_DEBUG
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
                {cout << "\nInvalid key length; Key too short! For help, run DES with no arguments."
                      << "\nYour <key> = " << argv[2] << endl; return 0;}
            if(argv[2][i] == '\'')
                {cout << "\nInvalid key length; Key too short! Single quote character not allowed before 8 character. "
                         << "For help, run DES with no arguments.\nYour <key> = " << argv[2] << endl; return 0;}

            // j = index for bit location within 64 bit key container
            // k = index for bit location within a single character
            // go through every bit of every character in argument and set appropriate bits in 64 bit key container
            for(int k = 7; k >= 0; --j, --k) {
                if(argv[2][i] & (1 << k)) key |= (1ULL << j);
            }
        }
        // check for long key arguments
        if((argv[2][9] != '\'' && argv[2][9] != 0) || (argv[2][9] == '\'' && argv[2][10] != 0))
            {cout << "\nInvalid key length; Key too long! For help, run DES with no arguments."
                  << "\nYour <key> = " << argv[2] << endl; return 0;}
    }
    else if(isxdigit(argv[2][0])){
        // go through argument's 16 hex digits (64 bits)
        for(int i = 0; i < 16; ++i){
            // check for short key arguments or invalid hex digits
            // 0 (null terminating char) will appear at the end of every argument from command line
            if(argv[2][i] == 0)
                {cout << "\nKey too short! Require 64 bit HEX value (without 0x prefix). "
                      << "For help, run DES with no arguments.\nYour <key> = " << argv[2] << endl; return 0;}
            if(!isxdigit(argv[2][i]))
                {cout << "\nInvalid key! Key is not a HEX value! Require 64 bit HEX value (without 0x prefix). "
                      << "For help, run DES with no arguments.\nYour <key> = " << argv[2] << endl; return 0;}

            // extract numerical hex value from character
            // '0' = 0x30 ascii; '3' - '0' = 0x33 - 0x30 = 0x03 = 3 decimal
            int hex_val = toupper(argv[2][i]) - '0';
            // if character is non-numeric (i.e. 'A', 'B', 'C', ...)
            // 'A' = 0x41; 'A' - '0' - 7 decimal = 0x41 - 0x30 - 0x07 = 0x0A = 10 decimal
            if(hex_val > 9) hex_val -= 7;
            key |= (uint64_t)hex_val << ((15 - i) * 4); // set appropriate bits in 64 bit container
        }
        // check for long key arguments
        if(argv[2][16] != 0)
            {cout << "\nKey too long! Require 64 bit HEX value (without 0x prefix). "
                  << "For help, run DES with no arguments.\nYour <key> = " << argv[2] << endl; return 0;}
    }
    else {
        cout << "Invalid <key> argument! Must begin with single quote character or HEX value (without 0x prefix). "
             << "For help, run DES with no arguments.\nYour <key> = " << argv[2] << endl;
        return 0;
    }
    uint64_t badkey1 = 0ULL;
    uint64_t badkey2 = 0xFFFFFFFFFFFFFFFF;
    uint64_t badkey3 = 0xFFFFFFFF00000000;
    uint64_t badkey4 = 0x00000000FFFFFFFF;
    if(key == badkey1 || key == badkey2 || key == badkey3 || key == badkey4)
        {cout << "\nThe key used will not work well with DES. Please choose a better key.\nExiting DES.\n"; return 0;}
    #ifdef VERBOSE_DEBUG
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
        {cout << "\nInvalid <mode> argument; Only ECB mode supported. "
              << "For help, run DES with no arguments.\nYour <mode> = " << argv[3] << endl; return 0;}
    ecbMode = true;
    #ifdef VERBOSE_DEBUG
    cout << "\tbool ecbMode = ";
    if(ecbMode) cout << "TRUE" << endl;
    else cout << "FALSE" << endl;
    #endif

    // check if infile == outfile
    if(!strcmp(argv[4], argv[5])) {cout << "\nError: <infile> cannot be the same as <outfile>\n"; return 0;}

    // <infile>
    // attempt to open the input file as binary input stream
    infile.open(argv[4], fstream::in | fstream::binary);
    if(infile.fail()) {cout << "\nFailed to open \"" << argv[4] << "\"" << endl; return 0;}
    #ifdef VERBOSE_DEBUG
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
        if(tolower(overwrite) == 'n') {cout << "Exiting DES\n"; return 0;}
        else if(tolower(overwrite) != 'y') {cout << "Invalid input; Exiting DES\n"; return 0;}
        // if overwrite allowed, open output file as truncated binary output stream
        // trunc discards any contents that existed in file
        outfile.open(argv[5], fstream::out | fstream::binary | fstream::trunc);
        if(outfile.fail()) {cout << "\nFailed to open \"" << argv[5] << "\"" << endl; return 0;}
        #ifdef VERBOSE_DEBUG
        cout << "\tSuccessfully opened  \"" << argv[5] << "\"" << endl;
        #endif
    }
    else if(outfile.fail()){
        // if output file does not exist, create output file and open as binary output stream
        outfile.open(argv[5], fstream::out | fstream::binary);
        if(outfile.fail()) {cout << "\nFailed to create \"" << argv[5] << "\"" << endl; return 0;}
        #ifdef VERBOSE_DEBUG
        cout << "\tSuccessfully created \"" << argv[5] << "\"" << endl;
        #endif
    }

    // Get the input file's size in bytes
    infile.seekg(0, infile.end); // put cursor at end of file to count its byte length
    // if file larger than 2 billion (and change) bytes
    if (infile.tellg() > 0x7fffffff) {
        cout << endl << argv[4] << " file size too large."
             << "\nMust be between 0 and 2,147,483,647 bytes long. Exiting DES\n";
        return 0;
    }
    infile_byte_length = (uint64_t) infile.tellg(); // save file size in bytes
    bytes_remaining = (unsigned int)infile.tellg();
    infile.seekg(0, infile.beg); // put cursor at beginning of file


    // ------------------------------------------------------------------------
    // Generate sixteen 48 bit round keys (for each of DES's sixteen rounds)
    // from the given 64 bit key and store them in roundkey[]
    // ------------------------------------------------------------------------

    #ifdef VERBOSE_DEBUG
    cout << "\nGenerating sixteen 48 bit round keys:";
    #endif

    // Compress 64 bit key to 56 bit permuted key ----------------------/
    uint64_t compressed_56_bit_key = 0;

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

    #ifdef VERBOSE_DEBUG
    cout << "\n\tcompressed_56_bit_key = ";
    print64(compressed_56_bit_key, 'b');
    cout << "\n\t                      = ";
    print64(compressed_56_bit_key, 'x');
    cout << endl;
    #endif

    // Compute the sixteen 48 bit round keys -----------------------------------/
    uint64_t left;
    uint64_t right;
    uint64_t compressed_48_bit_key;

    for(int i = 0; i < 16; ++i){
        // split compressed 56 bit key in half
        left  = compressed_56_bit_key >> 28;
        right = compressed_56_bit_key & 0x0000000FFFFFFF;

        if(i == 0 || i == 1 || i == 8 || i == 15){
            // rotate left (circular shift) by 1 bit
            left = ((left << 1) | (left >> 27)) & 0x0fffffff;
            right = ((right << 1) | (right >> 27)) & 0x0fffffff;
        }
        else {
            // rotate left (circular shift) by 2 bits
            left = ((left << 2) | (left >> 26)) & 0x0fffffff;
            right = ((right << 2) | (right >> 26)) & 0x0fffffff;
        }

        // combine both rotated 28 bit halves
        compressed_56_bit_key = (left << 28) | right;

        compressed_48_bit_key = 0;

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
        if(compressed_56_bit_key & (1ULL << 11)) compressed_48_bit_key |= (1ULL << (48 - 34));
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

        #ifdef VERBOSE_DEBUG
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
        #ifdef VERBOSE_DEBUG
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
        #ifdef VERBOSE_DEBUG
        cout << "\n\tGenerated 64 bit block with left 33 bits as random and right 31 bits as file size in bytes" << endl;
        cout << "\t\t<infile> size = 0d" << infile_byte_length << " bytes";
        printf("\n\t\t              = 0x%llX bytes", infile_byte_length);
        cout << "\n\t\tfile size block = ";
        print64(block, 'b');
        cout << "\n\t\t                = ";
        print64(block, 'x');
        cout << endl;

        cout << "\nEncrypting..." << endl;
        #endif

        // Encrypt block
        DES();

        // write encrypted block (containing 33 bits of garbage and 31 bits of file length) to <outfile>
        writeBlock();

        while(bytes_remaining){
            readBlock();
            DES(); // Encrypt block
            writeBlock();
        }

        cout << "\nSuccessfully ran DES encryption algorithm!";
    }
    else{
        #ifdef VERBOSE_DEBUG
        cout << "\nDecryption:";
        #endif

        if(infile_byte_length < 8) {cout << "\nInput file size too small. Exiting DES.\n"; return 0;}
        if(infile_byte_length % 8) {cout << "\nInput file size not multiple of 8. Exiting DES.\n"; return 0;}

        // read first block containing original file length
        readBlock();

        // Decrypt block
        DES();

        // extract file length value by bit masking
        bytes_remaining = (unsigned int)(block & 0x000000007fffffff);

        // verify decrypted file length makes sense
        if(bytes_remaining > (infile_byte_length - 8) || bytes_remaining < (infile_byte_length - 15))
            {cout << "\nError with decrypted file length (= "
                  << bytes_remaining << " bytes). Exiting DES.\n"; return 0;}

        unsigned int total_bytes = bytes_remaining;
        #ifdef VERBOSE_DEBUG
        cout << "\n\tDecrypting " << total_bytes << " bytes (" << ceil(total_bytes / 8) << " blocks)\n";
        #endif

        // read, decrypt, and write until no more bytes left
        while(bytes_remaining){
            readBlock();
            DES(); // Decrypt block
            writeBlock();
        }

        cout << "\nSuccessfully ran DES decryption algorithm!";
    }

    // print out time statistics
    cout << "\nElapsed time = " << (float)(clock() - start_time)/CLOCKS_PER_SEC << " seconds.\nDone\n\n";

    return 0;
}

// Data Encryption Standard
// Here, we'll run the 64 bit block through the DES algorithm to
// encrypt or decrypt the block.
// 1) run block through initial permutation
// 2) run block through the 16 rounds
//      2.1) Split 64 bit input into left and right 32 bit halves
//      2.2) Expand 32 bit right half into 48 bit permuted right half
//      2.3) Mixer step; mix 48 bit right half with appropriate 48 bit roundkey[]
//           mix keys forwards if encrypting, backwards if decrypting
//      2.4) Run 48 bit right half through the substitution boxes to get new 32 bit right half
//      2.5) Run 32 bit right half through a 32 bit permutation
//      2.6) Combine (XOR) original left half with new (highly modified) right half
//      2.7) Merge left and right half into 64 bit block
// 3) swap resulting block's left and right half one more time
// 4) run block through final permutation
void DES(){

    // ------------------------------------------------------------------------
    // Initial Permutation
    // ------------------------------------------------------------------------

    DES_rounds_block = 0;

    if(block & (1ULL << 63)) DES_rounds_block |= (1ULL << (64 - 40));
    if(block & (1ULL << 62)) DES_rounds_block |= (1ULL << (64 - 8));
    if(block & (1ULL << 61)) DES_rounds_block |= (1ULL << (64 - 48));
    if(block & (1ULL << 60)) DES_rounds_block |= (1ULL << (64 - 16));
    if(block & (1ULL << 59)) DES_rounds_block |= (1ULL << (64 - 56));
    if(block & (1ULL << 58)) DES_rounds_block |= (1ULL << (64 - 24));
    if(block & (1ULL << 57)) DES_rounds_block |= (1ULL << (64 - 64));
    if(block & (1ULL << 56)) DES_rounds_block |= (1ULL << (64 - 32));
    if(block & (1ULL << 55)) DES_rounds_block |= (1ULL << (64 - 39));
    if(block & (1ULL << 54)) DES_rounds_block |= (1ULL << (64 - 7));
    if(block & (1ULL << 53)) DES_rounds_block |= (1ULL << (64 - 47));
    if(block & (1ULL << 52)) DES_rounds_block |= (1ULL << (64 - 15));
    if(block & (1ULL << 51)) DES_rounds_block |= (1ULL << (64 - 55));
    if(block & (1ULL << 50)) DES_rounds_block |= (1ULL << (64 - 23));
    if(block & (1ULL << 49)) DES_rounds_block |= (1ULL << (64 - 63));
    if(block & (1ULL << 48)) DES_rounds_block |= (1ULL << (64 - 31));

    if(block & (1ULL << 47)) DES_rounds_block |= (1ULL << (64 - 38));
    if(block & (1ULL << 46)) DES_rounds_block |= (1ULL << (64 - 6));
    if(block & (1ULL << 45)) DES_rounds_block |= (1ULL << (64 - 46));
    if(block & (1ULL << 44)) DES_rounds_block |= (1ULL << (64 - 14));
    if(block & (1ULL << 43)) DES_rounds_block |= (1ULL << (64 - 54));
    if(block & (1ULL << 42)) DES_rounds_block |= (1ULL << (64 - 22));
    if(block & (1ULL << 41)) DES_rounds_block |= (1ULL << (64 - 62));
    if(block & (1ULL << 40)) DES_rounds_block |= (1ULL << (64 - 30));
    if(block & (1ULL << 39)) DES_rounds_block |= (1ULL << (64 - 37));
    if(block & (1ULL << 38)) DES_rounds_block |= (1ULL << (64 - 5));
    if(block & (1ULL << 37)) DES_rounds_block |= (1ULL << (64 - 45));
    if(block & (1ULL << 36)) DES_rounds_block |= (1ULL << (64 - 13));
    if(block & (1ULL << 35)) DES_rounds_block |= (1ULL << (64 - 53));
    if(block & (1ULL << 34)) DES_rounds_block |= (1ULL << (64 - 21));
    if(block & (1ULL << 33)) DES_rounds_block |= (1ULL << (64 - 61));
    if(block & (1ULL << 32)) DES_rounds_block |= (1ULL << (64 - 29));

    if(block & (1ULL << 31)) DES_rounds_block |= (1ULL << (64 - 36));
    if(block & (1ULL << 30)) DES_rounds_block |= (1ULL << (64 - 4));
    if(block & (1ULL << 29)) DES_rounds_block |= (1ULL << (64 - 44));
    if(block & (1ULL << 28)) DES_rounds_block |= (1ULL << (64 - 12));
    if(block & (1ULL << 27)) DES_rounds_block |= (1ULL << (64 - 52));
    if(block & (1ULL << 26)) DES_rounds_block |= (1ULL << (64 - 20));
    if(block & (1ULL << 25)) DES_rounds_block |= (1ULL << (64 - 60));
    if(block & (1ULL << 24)) DES_rounds_block |= (1ULL << (64 - 28));
    if(block & (1ULL << 23)) DES_rounds_block |= (1ULL << (64 - 35));
    if(block & (1ULL << 22)) DES_rounds_block |= (1ULL << (64 - 3));
    if(block & (1ULL << 21)) DES_rounds_block |= (1ULL << (64 - 43));
    if(block & (1ULL << 20)) DES_rounds_block |= (1ULL << (64 - 11));
    if(block & (1ULL << 19)) DES_rounds_block |= (1ULL << (64 - 51));
    if(block & (1ULL << 18)) DES_rounds_block |= (1ULL << (64 - 19));
    if(block & (1ULL << 17)) DES_rounds_block |= (1ULL << (64 - 59));
    if(block & (1ULL << 16)) DES_rounds_block |= (1ULL << (64 - 27));

    if(block & (1ULL << 15)) DES_rounds_block |= (1ULL << (64 - 34));
    if(block & (1ULL << 14)) DES_rounds_block |= (1ULL << (64 - 2));
    if(block & (1ULL << 13)) DES_rounds_block |= (1ULL << (64 - 42));
    if(block & (1ULL << 12)) DES_rounds_block |= (1ULL << (64 - 10));
    if(block & (1ULL << 11)) DES_rounds_block |= (1ULL << (64 - 50));
    if(block & (1ULL << 10)) DES_rounds_block |= (1ULL << (64 - 18));
    if(block & (1ULL << 9)) DES_rounds_block |= (1ULL << (64 - 58));
    if(block & (1ULL << 8)) DES_rounds_block |= (1ULL << (64 - 26));
    if(block & (1ULL << 7)) DES_rounds_block |= (1ULL << (64 - 33));
    if(block & (1ULL << 6)) DES_rounds_block |= (1ULL << (64 - 1));
    if(block & (1ULL << 5)) DES_rounds_block |= (1ULL << (64 - 41));
    if(block & (1ULL << 4)) DES_rounds_block |= (1ULL << (64 - 9));
    if(block & (1ULL << 3)) DES_rounds_block |= (1ULL << (64 - 49));
    if(block & (1ULL << 2)) DES_rounds_block |= (1ULL << (64 - 17));
    if(block & (1ULL << 1)) DES_rounds_block |= (1ULL << (64 - 57));
    if(block & (1ULL << 0)) DES_rounds_block |= (1ULL << (64 - 25));

    // ------------------------------------------------------------------------
    // Go through the 16 Rounds
    // ------------------------------------------------------------------------

    for(int round = 0; round < 16; ++round){
        // Split 64 bit input into left and right 32 bit halves
        DES_left32 = DES_rounds_block >> 32;
        DES_right32 = DES_rounds_block & 0x00000000ffffffff;
        saved_right32 = DES_right32;

        // Expand 32 bit right half into 48 bit permuted right half
        uint64_t right48 = 0;
        if(DES_right32 & (1ULL << 31)) { right48 |= ((1ULL << (48 - 2)) | (1ULL << (48 - 48)));}
        if(DES_right32 & (1ULL << 30)) right48 |= (1ULL << (48 - 3));
        if(DES_right32 & (1ULL << 29)) right48 |= (1ULL << (48 - 4));
        if(DES_right32 & (1ULL << 28)) { right48 |= ((1ULL << (48 - 5)) | (1ULL << (48 - 7)));}
        if(DES_right32 & (1ULL << 27)) { right48 |= ((1ULL << (48 - 6)) | (1ULL << (48 - 8)));}
        if(DES_right32 & (1ULL << 26)) right48 |= (1ULL << (48 - 9));
        if(DES_right32 & (1ULL << 25)) right48 |= (1ULL << (48 - 10));
        if(DES_right32 & (1ULL << 24)) { right48 |= ((1ULL << (48 - 11)) | (1ULL << (48 - 13)));}
        if(DES_right32 & (1ULL << 23)) { right48 |= ((1ULL << (48 - 12)) | (1ULL << (48 - 14)));}
        if(DES_right32 & (1ULL << 22)) right48 |= (1ULL << (48 - 15));
        if(DES_right32 & (1ULL << 21)) right48 |= (1ULL << (48 - 16));
        if(DES_right32 & (1ULL << 20)) { right48 |= ((1ULL << (48 - 17)) | (1ULL << (48 - 19)));}
        if(DES_right32 & (1ULL << 19)) { right48 |= ((1ULL << (48 - 18)) | (1ULL << (48 - 20)));}
        if(DES_right32 & (1ULL << 18)) right48 |= (1ULL << (48 - 21));
        if(DES_right32 & (1ULL << 17)) right48 |= (1ULL << (48 - 22));
        if(DES_right32 & (1ULL << 16)) { right48 |= ((1ULL << (48 - 23)) | (1ULL << (48 - 25)));}
        if(DES_right32 & (1ULL << 15)) { right48 |= ((1ULL << (48 - 24)) | (1ULL << (48 - 26)));}
        if(DES_right32 & (1ULL << 14)) right48 |= (1ULL << (48 - 27));
        if(DES_right32 & (1ULL << 13)) right48 |= (1ULL << (48 - 28));
        if(DES_right32 & (1ULL << 12)) { right48 |= ((1ULL << (48 - 29)) | (1ULL << (48 - 31)));}
        if(DES_right32 & (1ULL << 11)) { right48 |= ((1ULL << (48 - 30)) | (1ULL << (48 - 32)));}
        if(DES_right32 & (1ULL << 10)) right48 |= (1ULL << (48 - 33));
        if(DES_right32 & (1ULL << 9)) right48 |= (1ULL << (48 - 34));
        if(DES_right32 & (1ULL << 8)) { right48 |= ((1ULL << (48 - 35)) | (1ULL << (48 - 37)));}
        if(DES_right32 & (1ULL << 7)) { right48 |= ((1ULL << (48 - 36)) | (1ULL << (48 - 38)));}
        if(DES_right32 & (1ULL << 6)) right48 |= (1ULL << (48 - 39));
        if(DES_right32 & (1ULL << 5)) right48 |= (1ULL << (48 - 40));
        if(DES_right32 & (1ULL << 4)) { right48 |= ((1ULL << (48 - 41)) | (1ULL << (48 - 43)));}
        if(DES_right32 & (1ULL << 3)) { right48 |= ((1ULL << (48 - 42)) | (1ULL << (48 - 44)));}
        if(DES_right32 & (1ULL << 2)) right48 |= (1ULL << (48 - 45));
        if(DES_right32 & (1ULL << 1)) right48 |= (1ULL << (48 - 46));
        if(DES_right32 & (1ULL << 0)) { right48 |= ((1ULL << (48 - 47)) | (1ULL << (48 - 1)));}

        // Mixer step; mix right48 with appropriate 48 bit roundkey[]
        // mix keys forwards if encrypting, backwards if decrypting
        if(encrypt) right48 ^= roundkey[round];
        else        right48 ^= roundkey[15 - round];

        DES_right32 = 0;

//        cout << "\nright48 = ";
//        print64(right48, 'b');
//        cout << "\n        = ";
//        print64(right48, 'x');

        // Substitution boxes (S-Boxes)
        // 1) Divide the 48 bit right half into eight 6 bit chunks
        // 2) Each s-box (s1, s2, ...) has 4 rows (0 thru 3) and 16 columns (0 thru 15)
        // 3) Take first and last bit of each chunk to determine row, middle 4 bits determine column
        //    ex. abcdef = a bcde f = af bcde
        //    ex. 110100 = 1 1010 0 = 10 1010 = value at row 2 col 10 for specific s-box
        // 4) Use s1[i][j]; returns the value at row i col j from s1
        // 5) shift value returned by appropriate s-box into appropriate location in 32 bit right half block
        DES_right32 |= (uint64_t)(s1[(((right48 >> 46) & 0b10) | ((right48 >> 42) & 0b000001))][((right48 >> 43) & 0b01111)]) << 28;
        DES_right32 |= (uint64_t)(s2[(((right48 >> 40) & 0b10) | ((right48 >> 36) & 0b000001))][((right48 >> 37) & 0b01111)]) << 24;
        DES_right32 |= (uint64_t)(s3[(((right48 >> 34) & 0b10) | ((right48 >> 30) & 0b000001))][((right48 >> 31) & 0b01111)]) << 20;
        DES_right32 |= (uint64_t)(s4[(((right48 >> 28) & 0b10) | ((right48 >> 24) & 0b000001))][((right48 >> 25) & 0b01111)]) << 16;
        DES_right32 |= (uint64_t)(s5[(((right48 >> 22) & 0b10) | ((right48 >> 18) & 0b000001))][((right48 >> 19) & 0b01111)]) << 12;
        DES_right32 |= (uint64_t)(s6[(((right48 >> 16) & 0b10) | ((right48 >> 12) & 0b000001))][((right48 >> 13) & 0b01111)]) << 8;
        DES_right32 |= (uint64_t)(s7[(((right48 >> 10) & 0b10) | ((right48 >> 6) & 0b000001))][((right48 >> 7) & 0b01111)]) << 4;
        DES_right32 |= (uint64_t)(s8[(((right48 >> 4) & 0b10) | ((right48) & 0b000001))][((right48 >> 1) & 0b01111)]);

//        DES_right32 |= (uint64_t)(s1[((((right48 >> 46) & 0b10) | ((right48 >> 42) & 0b000001)) << 4) + ((right48 >> 43) & 0b01111)]) << 28;
//        DES_right32 |= (uint64_t)(s2[((((right48 >> 40) & 0b10) | ((right48 >> 36) & 0b000001)) << 4) + (((right48 >> 37) & 0b01111))]) << 24;
//        DES_right32 |= (uint64_t)(s3[((((right48 >> 34) & 0b10) | ((right48 >> 30) & 0b000001)) << 4) + (((right48 >> 31) & 0b01111))]) << 20;
//        DES_right32 |= (uint64_t)(s4[((((right48 >> 28) & 0b10) | ((right48 >> 24) & 0b000001)) << 4) + (((right48 >> 25) & 0b01111))]) << 16;
//        DES_right32 |= (uint64_t)(s5[((((right48 >> 22) & 0b10) | ((right48 >> 18) & 0b000001)) << 4) + (((right48 >> 19) & 0b01111))]) << 12;
//        DES_right32 |= (uint64_t)(s6[((((right48 >> 16) & 0b10) | ((right48 >> 12) & 0b000001)) << 4) + (((right48 >> 13) & 0b01111))]) << 8;
//        DES_right32 |= (uint64_t)(s7[((((right48 >> 10) & 0b10) | ((right48 >> 6) & 0b000001)) << 4) + (((right48 >> 7) & 0b01111))]) << 4;
//        DES_right32 |= (uint64_t)(s8[((((right48 >> 4) & 0b10) | ((right48) & 0b000001)) << 4) + (((right48 >> 1) & 0b01111))]);

//        uint64_t temp32 = DES_right32;
//        cout << "\nright32 = ";
//        print64(temp32, 'b');
//        cout << "\n        = ";
//        print64(temp32, 'x');
//        cout << endl << endl;


        // Post S-Box right side permutation
        uint64_t temp = DES_right32;
        DES_right32 = 0;
        if(temp & (1ULL << 31)) DES_right32 |= (1ULL << (32 - 9));
        if(temp & (1ULL << 30)) DES_right32 |= (1ULL << (32 - 17));
        if(temp & (1ULL << 29)) DES_right32 |= (1ULL << (32 - 23));
        if(temp & (1ULL << 28)) DES_right32 |= (1ULL << (32 - 31));
        if(temp & (1ULL << 27)) DES_right32 |= (1ULL << (32 - 13));
        if(temp & (1ULL << 26)) DES_right32 |= (1ULL << (32 - 28));
        if(temp & (1ULL << 25)) DES_right32 |= (1ULL << (32 - 2));
        if(temp & (1ULL << 24)) DES_right32 |= (1ULL << (32 - 18));
        if(temp & (1ULL << 23)) DES_right32 |= (1ULL << (32 - 24));
        if(temp & (1ULL << 22)) DES_right32 |= (1ULL << (32 - 16));
        if(temp & (1ULL << 21)) DES_right32 |= (1ULL << (32 - 30));
        if(temp & (1ULL << 20)) DES_right32 |= (1ULL << (32 - 6));
        if(temp & (1ULL << 19)) DES_right32 |= (1ULL << (32 - 26));
        if(temp & (1ULL << 18)) DES_right32 |= (1ULL << (32 - 20));
        if(temp & (1ULL << 17)) DES_right32 |= (1ULL << (32 - 10));
        if(temp & (1ULL << 16)) DES_right32 |= (1ULL << (32 - 1));

        if(temp & (1ULL << 15)) DES_right32 |= (1ULL << (32 - 8));
        if(temp & (1ULL << 14)) DES_right32 |= (1ULL << (32 - 14));
        if(temp & (1ULL << 13)) DES_right32 |= (1ULL << (32 - 25));
        if(temp & (1ULL << 12)) DES_right32 |= (1ULL << (32 - 3));
        if(temp & (1ULL << 11)) DES_right32 |= (1ULL << (32 - 4));
        if(temp & (1ULL << 10)) DES_right32 |= (1ULL << (32 - 29));
        if(temp & (1ULL << 9)) DES_right32 |= (1ULL << (32 - 11));
        if(temp & (1ULL << 8)) DES_right32 |= (1ULL << (32 - 19));
        if(temp & (1ULL << 7)) DES_right32 |= (1ULL << (32 - 32));
        if(temp & (1ULL << 6)) DES_right32 |= (1ULL << (32 - 12));
        if(temp & (1ULL << 5)) DES_right32 |= (1ULL << (32 - 22));
        if(temp & (1ULL << 4)) DES_right32 |= (1ULL << (32 - 7));
        if(temp & (1ULL << 3)) DES_right32 |= (1ULL << (32 - 5));
        if(temp & (1ULL << 2)) DES_right32 |= (1ULL << (32 - 27));
        if(temp & (1ULL << 1)) DES_right32 |= (1ULL << (32 - 15));
        if(temp & (1ULL << 0)) DES_right32 |= (1ULL << (32 - 21));

        // Combine left half with new (highly modified) right half
        DES_right32 ^= DES_left32;

        // Merge left and right half
        DES_rounds_block = (saved_right32 << 32) | DES_right32;
    }

    // Split resulting rounds block and swap left and right halves one more time
    DES_left32 = DES_rounds_block >> 32;
    DES_right32 = DES_rounds_block & 0x00000000ffffffff;

    // Merge left and right half
    DES_rounds_block = (DES_right32 << 32) | DES_left32;


    // ------------------------------------------------------------------------
    // Final Permutation
    // ------------------------------------------------------------------------

    block = 0;

    if(DES_rounds_block & (1ULL << 63)) block |= (1ULL << (64 - 58));
    if(DES_rounds_block & (1ULL << 62)) block |= (1ULL << (64 - 50));
    if(DES_rounds_block & (1ULL << 61)) block |= (1ULL << (64 - 42));
    if(DES_rounds_block & (1ULL << 60)) block |= (1ULL << (64 - 34));
    if(DES_rounds_block & (1ULL << 59)) block |= (1ULL << (64 - 26));
    if(DES_rounds_block & (1ULL << 58)) block |= (1ULL << (64 - 18));
    if(DES_rounds_block & (1ULL << 57)) block |= (1ULL << (64 - 10));
    if(DES_rounds_block & (1ULL << 56)) block |= (1ULL << (64 - 2));
    if(DES_rounds_block & (1ULL << 55)) block |= (1ULL << (64 - 60));
    if(DES_rounds_block & (1ULL << 54)) block |= (1ULL << (64 - 52));
    if(DES_rounds_block & (1ULL << 53)) block |= (1ULL << (64 - 44));
    if(DES_rounds_block & (1ULL << 52)) block |= (1ULL << (64 - 36));
    if(DES_rounds_block & (1ULL << 51)) block |= (1ULL << (64 - 28));
    if(DES_rounds_block & (1ULL << 50)) block |= (1ULL << (64 - 20));
    if(DES_rounds_block & (1ULL << 49)) block |= (1ULL << (64 - 12));
    if(DES_rounds_block & (1ULL << 48)) block |= (1ULL << (64 - 4));

    if(DES_rounds_block & (1ULL << 47)) block |= (1ULL << (64 - 62));
    if(DES_rounds_block & (1ULL << 46)) block |= (1ULL << (64 - 54));
    if(DES_rounds_block & (1ULL << 45)) block |= (1ULL << (64 - 46));
    if(DES_rounds_block & (1ULL << 44)) block |= (1ULL << (64 - 38));
    if(DES_rounds_block & (1ULL << 43)) block |= (1ULL << (64 - 30));
    if(DES_rounds_block & (1ULL << 42)) block |= (1ULL << (64 - 22));
    if(DES_rounds_block & (1ULL << 41)) block |= (1ULL << (64 - 14));
    if(DES_rounds_block & (1ULL << 40)) block |= (1ULL << (64 - 6));
    if(DES_rounds_block & (1ULL << 39)) block |= (1ULL << (64 - 64));
    if(DES_rounds_block & (1ULL << 38)) block |= (1ULL << (64 - 56));
    if(DES_rounds_block & (1ULL << 37)) block |= (1ULL << (64 - 48));
    if(DES_rounds_block & (1ULL << 36)) block |= (1ULL << (64 - 40));
    if(DES_rounds_block & (1ULL << 35)) block |= (1ULL << (64 - 32));
    if(DES_rounds_block & (1ULL << 34)) block |= (1ULL << (64 - 24));
    if(DES_rounds_block & (1ULL << 33)) block |= (1ULL << (64 - 16));
    if(DES_rounds_block & (1ULL << 32)) block |= (1ULL << (64 - 8));

    if(DES_rounds_block & (1ULL << 31)) block |= (1ULL << (64 - 57));
    if(DES_rounds_block & (1ULL << 30)) block |= (1ULL << (64 - 49));
    if(DES_rounds_block & (1ULL << 29)) block |= (1ULL << (64 - 41));
    if(DES_rounds_block & (1ULL << 28)) block |= (1ULL << (64 - 33));
    if(DES_rounds_block & (1ULL << 27)) block |= (1ULL << (64 - 25));
    if(DES_rounds_block & (1ULL << 26)) block |= (1ULL << (64 - 17));
    if(DES_rounds_block & (1ULL << 25)) block |= (1ULL << (64 - 9));
    if(DES_rounds_block & (1ULL << 24)) block |= (1ULL << (64 - 1));
    if(DES_rounds_block & (1ULL << 23)) block |= (1ULL << (64 - 59));
    if(DES_rounds_block & (1ULL << 22)) block |= (1ULL << (64 - 51));
    if(DES_rounds_block & (1ULL << 21)) block |= (1ULL << (64 - 43));
    if(DES_rounds_block & (1ULL << 20)) block |= (1ULL << (64 - 35));
    if(DES_rounds_block & (1ULL << 19)) block |= (1ULL << (64 - 27));
    if(DES_rounds_block & (1ULL << 18)) block |= (1ULL << (64 - 19));
    if(DES_rounds_block & (1ULL << 17)) block |= (1ULL << (64 - 11));
    if(DES_rounds_block & (1ULL << 16)) block |= (1ULL << (64 - 3));

    if(DES_rounds_block & (1ULL << 15)) block |= (1ULL << (64 - 61));
    if(DES_rounds_block & (1ULL << 14)) block |= (1ULL << (64 - 53));
    if(DES_rounds_block & (1ULL << 13)) block |= (1ULL << (64 - 45));
    if(DES_rounds_block & (1ULL << 12)) block |= (1ULL << (64 - 37));
    if(DES_rounds_block & (1ULL << 11)) block |= (1ULL << (64 - 29));
    if(DES_rounds_block & (1ULL << 10)) block |= (1ULL << (64 - 21));
    if(DES_rounds_block & (1ULL << 9)) block |= (1ULL << (64 - 13));
    if(DES_rounds_block & (1ULL << 8)) block |= (1ULL << (64 - 5));
    if(DES_rounds_block & (1ULL << 7)) block |= (1ULL << (64 - 63));
    if(DES_rounds_block & (1ULL << 6)) block |= (1ULL << (64 - 55));
    if(DES_rounds_block & (1ULL << 5)) block |= (1ULL << (64 - 47));
    if(DES_rounds_block & (1ULL << 4)) block |= (1ULL << (64 - 39));
    if(DES_rounds_block & (1ULL << 3)) block |= (1ULL << (64 - 31));
    if(DES_rounds_block & (1ULL << 2)) block |= (1ULL << (64 - 23));
    if(DES_rounds_block & (1ULL << 1)) block |= (1ULL << (64 - 15));
    if(DES_rounds_block & (1ULL << 0)) block |= (1ULL << (64 - 7));

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