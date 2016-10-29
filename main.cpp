/*
 * Emilio Borges
 * October - November 8, 2016
 * University of Toledo - Undergrad Computer Science and Engineering
 * Computer Security - DES Programming Assignment
 *
 * Assignment Documentation: https://drive.google.com/open?id=0B4CF__kbczDjMGI0dklnZ2RxVTg
 *
 * Students are to implement the Data Encryption Standard (DES) algorithm and be able to
 * encrypt/decrypt any input file.
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
//#include <bitset>

#define DEBUG

using namespace std;

bool encrypt;
uint64_t key;
bool ecbMode;
fstream infile;
fstream outfile;

unsigned int infile_byte_length;

bool print64(uint64_t &value, char type);

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
    #endif

    // <-action>
    encrypt = false;
    if(argv[1][0] != '-' || argv[1][2] != 0)
        {cout << "\nInvalid <-action> argument! Only -e and -d allowed\n"; return 0;}
    if(tolower(argv[1][1]) == 'e') encrypt = true;
    else if(tolower(argv[1][1]) != 'd')
        {cout << "\nInvalid <-action> argument! Only -e and -d allowed\n"; return 0;}
    #ifdef DEBUG
    cout << "\nbool encrypt = ";
    if(encrypt) cout << "TRUE" << endl;
    else cout << "FALSE" << endl;
    #endif

    // <key>
    if(argv[2][0] == '\''){
        key = 0ULL; // http://stackoverflow.com/a/30777541
        for(int i = 1, j = 63; i < 9; ++i){
            if(argv[2][i] == 0)
                {cout << "\nInvalid key length; Key too short!\n"; return 0;}
            if(argv[2][i] == '\'')
                {cout << "\nInvalid key length; Key too short! single quote character not allowed\n"; return 0;}

            for(int k = 7; k >= 0; --j, --k) {
                if(argv[2][i] & (1 << k)) key |= (1ULL << j);
            }
        }
        if((argv[2][9] != '\'' && argv[2][9] != 0) || (argv[2][9] == '\'' && argv[2][10] != 0))
            {cout << "\nInvalid key length; Key too long!\n"; return 0;}
    }
    else if(isxdigit(argv[2][0])){
        for(int i = 0; i < 16; ++i){
            if(argv[2][i] == 0) {cout << "\nKey too short! Require 64 bit HEX value (without 0x prefix)\n"; return 0;}
            if(!isxdigit(argv[2][i]))
            {cout << "\nInvalid key! Key is not a HEX value! Require 64 bit HEX value (without 0x prefix)\n"; return 0;}

            int hex_val = toupper(argv[2][i]) - '0';
            if(hex_val > 9) hex_val -= 7;
            //cout << "argv[2][" << i << "] = " << hex_val << endl;
            key |= (uint64_t)hex_val << ((15 - i) * 4);
        }
        if(argv[2][16] != 0) {cout << "\nKey too long! Require 64 bit HEX value (without 0x prefix)\n"; return 0;}
    }
    else {
        cout << "Invalid <key> argument! Must begin with single quote character or HEX value (without 0x prefix)";
        return 0;
    }
    #ifdef DEBUG
    cout << "uint64_t key = 0d" << key << "\n             = 0b";
    if(print64(key, 'b')) return 0;
    cout << "\n             = ";
    if(print64(key, 'h')) return 0;
    cout << "\n             = ";
    if(print64(key, 's')) return 0;
    cout << endl;
    #endif

    // <mode>
    if(tolower(argv[3][0]) != 'e' || tolower(argv[3][1]) != 'c' || tolower(argv[3][2]) != 'b')
        {cout << "\nInvalid <mode> argument; Only ECB mode supported\n"; return 0;}
    ecbMode = true;
    #ifdef DEBUG
    cout << "bool ecbMode = ";
    if(ecbMode) cout << "TRUE" << endl;
    else cout << "FALSE" << endl;
    #endif

    // <infile>
    infile.open(argv[4], fstream::in | fstream::binary);
    if(infile.fail()) {cout << "\nFailed to open \"" << argv[4] << "\"" << endl; return 0;}
    #ifdef DEBUG
    cout << "\nSuccessfully opened  \"" << argv[4] << "\"" << endl;
    #endif

    // <outfile>
    outfile.open(argv[5], fstream::in);
    if(outfile.good()) {
        outfile.close();
        cout << "\n\"" << argv[5] << "\" already exists.\nOverwrite? [y/n]\n";
        char overwrite;
        cin >> overwrite;
        if(tolower(overwrite) == 'n') {cout << "Exiting DES"; return 0;}
        else if(tolower(overwrite) != 'y') {cout << "Invalid input; Exiting DES"; return 0;}
        outfile.open(argv[5], fstream::out | fstream::binary);
        if(outfile.fail()) {cout << "\nFailed to open \"" << argv[5] << "\"" << endl; return 0;}
        #ifdef DEBUG
        cout << "Successfully opened  \"" << argv[5] << "\"" << endl;
        #endif
    }
    else if(outfile.fail()){
        //outfile.close();
        outfile.open(argv[5], fstream::out | fstream::binary);
        if(outfile.fail()) {cout << "\nFailed to create \"" << argv[5] << "\"" << endl; return 0;}
        #ifdef DEBUG
        cout << "Successfully created \"" << argv[5] << "\"" << endl;
        #endif
    }




    // ------------------------------------------------------------------------
    // TODO Start working on DES crypto code
    // ------------------------------------------------------------------------



    return 0;
}


// cout the given 64 bit value in its binary, hex, or "string" representation
// char type defines cout as 'b' for binary, 'h' for hex, or 's' for string
// bool return false if successful cout with no errors, true if error occurred
bool print64(uint64_t &value, char type){

    switch(tolower(type)){

        case 'b': {
            for (int i = 63; i >= 0; --i) {
                if (value & (1ULL << i)) cout << "1";
                else cout << "0";
            }
            break;
        }

        case 'h': {
            printf("0x%016llX", value); // '016' = print 16 characters (will include leading zeros)
                                        // 'll'  = treat value as 64 bit (long long)
                                        // 'X'   = print as uppercase HEX value
            break;
        }

        case 's':{
            char key_string[8] = {0, 0, 0, 0, 0, 0, 0, 0};
            for(int i = 63, k = 0; i >=0; --i){
                if(key & (1ULL << i)) key_string[k] |= (1 << (i % 8));
                if(!(i % 8)) ++k;
            }
            cout << "\"";
            for(int i = 0; i < 8; ++i) cout << key_string[i];
            cout << "\"";
            break;
        }

        default:{
            cout << "\nUnknown type \'" << type << "\' as input parameter to print64(); Exiting DES\n";
            return true;
        }
    }

    return false;
}