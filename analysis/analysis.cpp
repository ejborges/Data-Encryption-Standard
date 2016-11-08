/*
 * Emilio Borges
 * October - November 8, 2016
 * University of Toledo - Undergrad Computer Science and Engineering
 * Computer Security - DES Programming Assignment - Analysis Portion
 *
 * Assignment Documentation: https://drive.google.com/open?id=0B4CF__kbczDjMGI0dklnZ2RxVTg
 * see last page -> paragraph above Graduate Students section
 *
 * Students are to implement the Data Encryption Standard (DES) algorithm and be able to
 * encrypt/decrypt any input file. Look at the assignment doc for more details.
 *
 * This program will analyze the given input (plaintext or encrypted) and perform statistical analysis such as
 * letter-frequency, bit-frequency, di-graphs, tri-graphs, averages, standard deviations,
 * distributions (normal and uniform), measure of how DES obscures input patterns in output file.
 *
 *
 * Any code not commented should be self explanatory (i.e. self documented) due to its simplicity
*/

#include <iostream>
#include <fstream>
#include <time.h>

#define VERBOSE_DEBUG

using namespace std;

fstream infile;
fstream outfile;
int infile_byte_length;
int bytes_remaining;
uint64_t block;
bool isPlaintext;

// function input/output defined with function definition
void print64(uint64_t &value, char type);
void readBlock();

int main(int argc, char *argv[]) {

    if(argc != 4) {cout << "\nNot enough arguments.\n"; exit(0);}

    //Are we analyzing plaintext or encrypted file?
    if(tolower(argv[1][0]) == 'p') isPlaintext = true;
    else if(tolower(argv[1][0]) == 'e') isPlaintext = false;
    else {cout << "\nWrong argv[1]; Needs to be either p or e\n"; exit(0);}

    // check if infile == outfile
    if(!strcmp(argv[2], argv[3])) {cout << "\nError: <infile> cannot be the same as <outfile>\n"; return 0;}

    // <infile>
    // attempt to open the input file as binary input stream
    infile.open(argv[2], fstream::in | fstream::binary);
    if(infile.fail()) {cout << "\nFailed to open \"" << argv[2] << "\"" << endl; return 0;}
    #ifdef VERBOSE_DEBUG
    cout << "\nFile Access:\n\tSuccessfully opened  \"" << argv[2] << "\"" << endl;
    #endif

    // <outfile>
    outfile.open(argv[3], fstream::in);
    // check if file already exists; ask to overwrite if so
    if(outfile.good()) {
        outfile.close();
        cout << "\n\t\"" << argv[3] << "\" already exists.\n\tOverwrite? [y/n]:";
        char overwrite;
        cin >> overwrite;
        if(tolower(overwrite) == 'n') {cout << "Exiting DES\n"; return 0;}
        else if(tolower(overwrite) != 'y') {cout << "Invalid input; Exiting DES\n"; return 0;}
        // if overwrite allowed, open output file as truncated binary output stream
        // trunc discards any contents that existed in file
        outfile.open(argv[3], fstream::out | fstream::binary | fstream::trunc);
        if(outfile.fail()) {cout << "\nFailed to open \"" << argv[3] << "\"" << endl; return 0;}
        #ifdef VERBOSE_DEBUG
        cout << "\tSuccessfully opened  \"" << argv[3] << "\"" << endl;
        #endif
    }
    else if(outfile.fail()){
        // if output file does not exist, create output file and open as binary output stream
        outfile.open(argv[3], fstream::out | fstream::binary);
        if(outfile.fail()) {cout << "\nFailed to create \"" << argv[3] << "\"" << endl; return 0;}
        #ifdef VERBOSE_DEBUG
        cout << "\tSuccessfully created \"" << argv[3] << "\"" << endl;
        #endif
    }

    // Get the input file's size in bytes
    infile.seekg(0, infile.end); // put cursor at end of file to count its byte length
    // if file larger than 2 billion (and change) bytes
    if (infile.tellg() > 0x7fffffff) {
        cout << endl << argv[2] << " file size too large."
        << "\nMust be between 0 and 2,147,483,647 bytes long. Exiting DES\n";
        return 0;
    }
    infile_byte_length = (int)infile.tellg(); // save file size in bytes
    bytes_remaining = (int)infile.tellg();
    infile.seekg(0, infile.beg); // put cursor at beginning of file


    unsigned int char_freq[256] = {0};
    unsigned int digraph_freq[256*256] = {0};
    unsigned int trigraph_freq[256*256*256] = {0};
    uint16_t digraph;
    uint32_t trigraph;
    uint8_t previous_char, previous_previous_char;
    bool first_round = true;


    if(isPlaintext){
        while(bytes_remaining){
            readBlock();

            // character-frequency
            ++char_freq[(uint8_t)((block & 0xff00000000000000) >> 56)];
            ++char_freq[(uint8_t)((block & 0x00ff000000000000) >> 48)];
            ++char_freq[(uint8_t)((block & 0x0000ff0000000000) >> 40)];
            ++char_freq[(uint8_t)((block & 0x000000ff00000000) >> 32)];
            ++char_freq[(uint8_t)((block & 0x00000000ff000000) >> 24)];
            ++char_freq[(uint8_t)((block & 0x0000000000ff0000) >> 16)];
            ++char_freq[(uint8_t)((block & 0x000000000000ff00) >> 8)];
            ++char_freq[(uint8_t)((block & 0x00000000000000ff))];

            // bit-frequency
            //TODO

            // di-graphs
            if(!first_round){
                digraph = ((uint16_t)previous_char << 8) | (uint8_t)((block & 0xff00000000000000) >> 56);
                ++digraph_freq[digraph];
            }
            for(uint64_t shiftby = 48, andby = 0x00ff000000000000; shiftby >= 0; shiftby -= 8, andby >>= 8) {
                digraph = (uint16_t)((block & ((uint64_t)andby << 8)) >> (shiftby + 8)) | (uint8_t)((block & andby) >> shiftby);
                ++digraph_freq[digraph];
            }


            // tri-graphs
            if(!first_round){
                trigraph = (((uint32_t)previous_previous_char << 16) | ((uint32_t)previous_char << 8))
                           | (uint8_t)((block & 0xff00000000000000) >> 56);
                ++trigraph_freq[trigraph];
                trigraph = (((uint32_t)previous_char << 16) | (uint32_t)((block & 0xff00000000000000) >> 48))
                           | (uint8_t)((block & 0x00ff000000000000) >> 48);
                ++trigraph_freq[trigraph];
            }
            for(uint64_t shiftby = 40, andby = 0x0000ff0000000000; shiftby >= 0; shiftby -= 8, andby >>= 8) {
                trigraph = (uint32_t)((block & ((uint64_t)andby << 16)) >> (shiftby + 16)) |
                            ((uint32_t)((block & ((uint64_t)andby << 8)) >> (shiftby + 8)) |
                                    (uint32_t)((block & andby) >> shiftby));
                ++trigraph_freq[trigraph];
            }


            // averages

            // standard deviations

            // distributions (normal and uniform)

            // measure of how DES obscures input patterns in output file




            previous_previous_char = (uint8_t)((block & 0x000000000000ff00) >> 8);
            previous_char = (uint8_t)((block & 0x00000000000000ff));
            first_round = false;
        }
    }
    else{
        // we're reading an encrypted file
        // discard the first block containing
        // random garbage and file length
        readBlock();

        while(bytes_remaining){
            readBlock();

            // character-frequency

            // bit-frequency

            // di-graphs

            // tri-graphs

            // averages

            // standard deviations

            // distributions (normal and uniform)

            // measure of how DES obscures input patterns in output file
        }
    }

    // Write analysis to file
    outfile << "Analysis of " << argv[3] << "\n\n";

    // character-frequency
    outfile << "Character Frequency\n"
            << "Char,ASCII,Freq\n";
    for(int i = 0; i < 256; ++i){
        outfile << i << ",";
        if(i < 32 || i == 127) outfile << " ,";
        else outfile << (char)i << ",";
        outfile << char_freq[i] << "\n";
    }
    outfile << "\n";

    // bit-frequency

    // di-graphs
    outfile << "Di-Graph Frequency\n"
            << "Chars,ASCII,Freq\n";
    for(uint16_t i = 0; i < (256*256); ++i){
        
    }


    // tri-graphs


    // averages

    // standard deviations

    // distributions (normal and uniform)

    // measure of how DES obscures input patterns in output file






    return 0;
}


// read 8 bytes from <infile> and places them in the global block variable
// if 8 bytes not available, read as many bytes as possible and fill in the rest with random chars
void readBlock(){
    if(!infile.is_open()) {cout << "\nError while reading from <infile>. File not open. Exiting DES."; exit(0);}

    block = 0;

    char buffer[8]; // storage for all 8 chars in 64 bits
    infile.read(buffer, 8); // read 8 bytes from infile and store them in buffer[]

    // if read() reaches end of file, it sets both eof and failbit flags
    if(infile.fail() && !infile.eof()) {cout << "\nError while reading from <infile>. Exiting DES."; exit(0);}

    // if end of file reached, fill the remaining bytes in buffer[] with random garbage
    if(infile.eof()) for(int i = (int)infile.gcount(); i < 8; ++i) buffer[i] = (unsigned char)(rand() % 256);

    bytes_remaining -= infile.gcount();

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
                if(value & (1ULL << i)) key_string[k] |= (1 << (i % 8));
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