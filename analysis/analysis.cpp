/*
* Emilio Borges
* October - November 8, 2016
* University of Toledo - Undergrad Computer Science and Engineering
* Computer Security - DES Programming Assignment - Analysis Portion
*
* Assignment Documentation: https://drive.google.com/open?id=0B4CF__kbczDjMGI0dklnZ2RxVTg
* For the instructions on this analysis, see last page -> paragraph above Graduate Students section
*
* Students are to implement the Data Encryption Standard (DES) algorithm and be able to
* encrypt/decrypt any input file. Look at the assignment doc for more details.
*
* This program will analyze the given input (plaintext or encrypted) and perform statistical analysis such as
* letter-frequency, bit-frequency, di-graphs, tri-graphs, octo-graphs, and averages
*
* The output will be formatted as comma separated values to be saved in a *.csv file and used with MS Excel
* In Excel, this data will be used to calculate standard deviations, distributions (normal and uniform), and 
* measure how DES obscures input patterns in the encrypted output file.
*
* Any code not commented should be self explanatory (i.e. self documented) due to its simplicity
*/

#include <iostream>
#include <fstream>
#include <cstdint>
#include <map>
#include <string>

#define VERBOSE_DEBUG

using namespace std;

fstream infile;
fstream outfile;
//int infile_byte_length;
int bytes_remaining;
uint64_t block;
bool isPlaintext;

// function input/output defined with function definition
void print64(uint64_t &value, char type);
void readBlock();

int main(int argc, char *argv[]) {

	if (argc != 4) { cout << "\nNot enough arguments.\n"; exit(0); }

	//Are we analyzing plaintext or encrypted file?
	if (tolower(argv[1][0]) == 'p') isPlaintext = true;
	else if (tolower(argv[1][0]) == 'e') isPlaintext = false;
	else { cout << "\nWrong argv[1]; Needs to be either p or e\n"; exit(0); }

	// check if infile == outfile
	if (!strcmp(argv[2], argv[3])) { cout << "\nError: <infile> cannot be the same as <outfile>\n"; return 0; }

	// <infile>
	// attempt to open the input file as binary input stream
	infile.open(argv[2], fstream::in | fstream::binary);
	if (infile.fail()) { cout << "\nFailed to open \"" << argv[2] << "\"" << endl; return 0; }
	#ifdef VERBOSE_DEBUG
	cout << "\nFile Access:\n\tSuccessfully opened  \"" << argv[2] << "\"" << endl;
	#endif

	// <outfile>
	outfile.open(argv[3], fstream::in);
	// check if file already exists; ask to overwrite if so
	if (outfile.good()) {
		outfile.close();
		cout << "\n\t\"" << argv[3] << "\" already exists.\n\tOverwrite? [y/n]:";
		char overwrite;
		cin >> overwrite;
		if (tolower(overwrite) == 'n') { cout << "Exiting DES\n"; return 0; }
		else if (tolower(overwrite) != 'y') { cout << "Invalid input; Exiting DES\n"; return 0; }
		// if overwrite allowed, open output file as truncated binary output stream
		// trunc discards any contents that existed in file
		outfile.open(argv[3], fstream::out | fstream::binary | fstream::trunc);
		if (outfile.fail()) { cout << "\nFailed to open \"" << argv[3] << "\"" << endl; return 0; }
		#ifdef VERBOSE_DEBUG
		cout << "\tSuccessfully opened  \"" << argv[3] << "\"" << endl;
		#endif
	}
	else if (outfile.fail()){
		// if output file does not exist, create output file and open as binary output stream
		outfile.open(argv[3], fstream::out | fstream::binary);
		if (outfile.fail()) { cout << "\nFailed to create \"" << argv[3] << "\"" << endl; return 0; }
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
	//infile_byte_length = (int)infile.tellg(); // save file size in bytes
	bytes_remaining = (int)infile.tellg();
	infile.seekg(0, infile.beg); // put cursor at beginning of file


	bool first_round = true;
	int bytes_read;
	unsigned int char_freq[256] = { 0 };
	uint16_t digraph;
	uint32_t trigraph;
	map<uint64_t, int> octographs;
	map<uint32_t, int> trigraphs;
	map<uint16_t, int> digraphs;
	uint8_t previous_char, previous_previous_char;
	int blocks_processed = 0;
	uint64_t ones_sum = 0;
	uint64_t zeros_sum = 0;
	int ones_per_location[64] = { 0 };
	int zeros_per_location[64] = { 0 };

	string char_code[256];
	char_code[0] = "[NUL]";		char_code[8] = "[BS]";		char_code[16] = "[DLE]";		char_code[24] = "[CAN]";		char_code[32] = "[Space]";
	char_code[1] = "[SOH]";		char_code[9] = "[TAB]";		char_code[17] = "[DC1]";		char_code[25] = "[EM]";			char_code[34] = "\"\"";
	char_code[2] = "[STX]";		char_code[10] = "[LF]";		char_code[18] = "[DC2]";		char_code[26] = "[SUB]";		char_code[44] = "\"\",\"\"";
	char_code[3] = "[ETX]";		char_code[11] = "[VT]";		char_code[19] = "[DC3]";		char_code[27] = "[ESC]";		char_code[127] = "[DEL]";
	char_code[4] = "[EOT]";		char_code[12] = "[FF]";		char_code[20] = "[DC4]";		char_code[28] = "[FS]";
	char_code[5] = "[ENQ]";		char_code[13] = "[CR]";		char_code[21] = "[NAK]";		char_code[29] = "[GS]";
	char_code[6] = "[ACK]";		char_code[14] = "[SO]";		char_code[22] = "[SYN]";		char_code[30] = "[RS]";
	char_code[7] = "[BEL]";		char_code[15] = "[SI]";		char_code[23] = "[ETB]";		char_code[31] = "[US]";

	


	if (!isPlaintext){
		// we're reading an encrypted file;
		// discard the first block containing
		// random garbage and file length
		readBlock();
	}

	while (bytes_remaining){
		bytes_read = bytes_remaining;
		readBlock();
		bytes_read -= bytes_remaining;

		// character-frequency
		++char_freq[(uint8_t)((block & 0xff00000000000000) >> 56)];
		if (bytes_read >= 2) ++char_freq[(uint8_t)((block & 0x00ff000000000000) >> 48)];
		if (bytes_read >= 3) ++char_freq[(uint8_t)((block & 0x0000ff0000000000) >> 40)];
		if (bytes_read >= 4) ++char_freq[(uint8_t)((block & 0x000000ff00000000) >> 32)];
		if (bytes_read >= 5) ++char_freq[(uint8_t)((block & 0x00000000ff000000) >> 24)];
		if (bytes_read >= 6) ++char_freq[(uint8_t)((block & 0x0000000000ff0000) >> 16)];
		if (bytes_read >= 7) ++char_freq[(uint8_t)((block & 0x000000000000ff00) >> 8)];
		if (bytes_read >= 8) ++char_freq[(uint8_t)((block & 0x00000000000000ff))];

		// di-graphs
		if (!first_round){
			digraph = (((uint16_t)previous_char) << 8) | (uint16_t)((block & 0xff00000000000000) >> 56);
			digraphs[digraph]++;
		}
		int di_index = 0;
		uint64_t andby = 0x00ff000000000000;
		for (int shiftby = 48; shiftby >= 0; shiftby -= 8, andby >>= 8) {
			if (di_index++ >= (bytes_read - 1)) break;
			//digraph = (uint16_t)((block & (andby << 8)) >> (shiftby + 8)) | (uint8_t)((block & andby) >> shiftby);
			digraph = (uint16_t)(((block & (andby << 8)) | (block & andby)) >> shiftby);
			digraphs[digraph]++;
		}

		// tri-graphs
		int tri_index = 0;
		if (!first_round){
			trigraph = (((uint32_t)previous_previous_char << 16) | ((uint32_t)previous_char << 8)) | (uint32_t)((block & 0xff00000000000000) >> 56);
			trigraphs[trigraph]++;
			if (tri_index++ < (bytes_read - 1)){
				trigraph = (((uint32_t)previous_char << 16) | (uint32_t)((block & 0xff00000000000000) >> 48)) | (uint32_t)((block & 0x00ff000000000000) >> 48);
				trigraphs[trigraph]++;
			}
		}
		andby = 0x0000ff0000000000;
		for (int shiftby = 40; shiftby >= 0; shiftby -= 8, andby >>= 8) {
			if (tri_index++ >= (bytes_read - 1)) break;
			//trigraph = (uint32_t)((block & (andby << 16)) >> (shiftby + 16)) | ((uint32_t)((block & (andby << 8)) >> (shiftby + 8)) | (uint32_t)((block & andby) >> shiftby));
			trigraph = (uint32_t)((block & (andby << 16)) >> shiftby) | ((uint32_t)((block & (andby << 8)) >> shiftby) | (uint32_t)((block & andby) >> shiftby));
			trigraphs[trigraph]++;
		}

		// octo-graphs
		if(bytes_read == 8) octographs[block]++;

		// bit-frequency (# of 1s and 0s in each block)
		int zeros, ones;
		zeros = ones = 0;
		if (bytes_remaining > 8){
			for (int i = 63; i >= 0; --i) {
				if (block & (1ULL << i)){
					++ones;
					++ones_per_location[i];
				}
				else {
					++zeros;
					++zeros_per_location[i];
				}
			}
			++blocks_processed;
			ones_sum += ones;
			zeros_sum += zeros;
		}

		previous_previous_char = (uint8_t)((block & 0x000000000000ff00) >> 8);
		previous_char = (uint8_t)((block & 0x00000000000000ff));
		first_round = false;
	}


	// Write analysis to file
	outfile << "Analysis of " << argv[2] << "\n\n";

	// character-frequency
	outfile << "Character Frequency\n"
		<< "ID,Freq,ASCII\n";
	for (int i = 0; i < 256; ++i){
		outfile << i << "," << char_freq[i] << ",";
		outfile << "\"";
		if (i < 33 || i == 127) outfile << char_code[i];
		else if (i == ',') outfile << char_code[i];
		else if (i == '"') outfile << char_code[i];
		else outfile << (char)i;
		outfile << "\"\n";
	}
	outfile << "\n";


	int uniqueness = 3;

	// di-graphs
	// if confused about quotes, see this: http://stackoverflow.com/a/4617967
	outfile << "Di-Graph Frequency\n"
		<< "ID,Freq,ASCII\n";
	unsigned char di_left;
	unsigned char di_right;
	for (map<uint16_t, int>::iterator it = digraphs.begin(); it != digraphs.end(); ++it){
		if (it->second < uniqueness) continue;
		outfile << "0x" << hex << it->first << "," << dec << it->second << ",";
		di_left = (unsigned char)((it->first) >> 8);
		di_right = (unsigned char)((it->first) & 0xff);
		outfile << "\" ";
		if (di_left < 33 || di_left == 127) outfile << char_code[di_left];
		else if (di_left == ',') outfile << char_code[di_left];
		else if (di_left == '"') outfile << char_code[di_left];
		else outfile << di_left;
		if (di_right < 33 || di_right == 127) outfile << char_code[di_right];
		else if (di_right == ',') outfile << char_code[di_right];
		else if (di_right == '"') outfile << char_code[di_right];
		else outfile << di_right;
		outfile << "\",\n";
	}
	outfile << "\n";

	// tri-graphs
	// if confused about quotes, see this: http://stackoverflow.com/a/4617967
	outfile << "Tri-Graph Frequency\n"
		<< "ID,Freq,ASCII\n";
	unsigned char tri_left;
	unsigned char tri_mid;
	unsigned char tri_right;
	for (map<uint32_t, int>::iterator it = trigraphs.begin(); it != trigraphs.end(); ++it){
		if (it->second < uniqueness) continue;
		outfile << "0x" << hex << it->first << "," << dec << it->second << ",";
		tri_left = (unsigned char)((it->first) >> 16);
		tri_mid = (unsigned char)(((it->first) >> 8) & 0xff);
		tri_right = (unsigned char)((it->first) & 0xff);
		outfile << "\" "; 
		if (tri_left < 33 || tri_left == 127) outfile << char_code[tri_left];
		else if (tri_left == ',') outfile << char_code[tri_left];
		else if (tri_left == '"') outfile << char_code[tri_left];
		else outfile << tri_left;
		if (tri_mid < 33 || tri_mid == 127) outfile << char_code[tri_mid];
		else if (tri_mid == ',') outfile << char_code[tri_mid];
		else if (tri_mid == '"') outfile << char_code[tri_mid];
		else outfile << tri_mid;
		if (tri_right < 33 || tri_right == 127) outfile << char_code[tri_right];
		else if (tri_right == ',') outfile << char_code[tri_right];
		else if (tri_right == '"') outfile << char_code[tri_right];
		else outfile << tri_right;
		outfile << "\",\n";
	}
	outfile << "\n";

	// octo-graph
	// if confused about quotes, see this: http://stackoverflow.com/a/4617967
	outfile << "Octo-Graph Frequency\n"
		<< "ID,Freq,ASCII\n";
	unsigned char x;
	uint64_t andby;
	bool placed_comma = false;
	for (map<uint64_t, int>::iterator it = octographs.begin(); it != octographs.end(); ++it){
		if (it->second < uniqueness) continue;
		outfile << "0x" << hex << it->first << "," << dec << it->second << ",";
		outfile << "\" ";
		andby = 0xff00000000000000;
		for (int shiftby = 56; shiftby >= 0; shiftby -= 8, andby >>= 8){
			x = (unsigned char)(((it->first) & andby) >> shiftby);
			if (x < 32 || x == 127) outfile << char_code[x];
			else if (x == ',') outfile << char_code[x];
			else if (x == '"') outfile << char_code[x];
			else outfile << x;
		}
		outfile << "\",\n";
	}
	outfile << "\n";

	// bit-frequency
	outfile << "Bit Frequency\n"
		<< "1s Average," << ((double)ones_sum / blocks_processed) << "\n"
		<< "0s Average," << ((double)zeros_sum / blocks_processed) << "\n"
		<< "Bit Location,Zeros,Ones\n";
	for (int i = 63; i >= 0; --i) outfile << i << "," << zeros_per_location[i] << "," << ones_per_location[i] << "\n";
	outfile << "\n";

	return 0;
}


// read 8 bytes from <infile> and places them in the global block variable
// if 8 bytes not available, read as many bytes as possible and fill in the rest with random chars
void readBlock(){
	if (!infile.is_open()) { cout << "\nError while reading from <infile>. File not open. Exiting DES."; exit(0); }

	block = 0;

	char buffer[8]; // storage for all 8 chars in 64 bits
	infile.read(buffer, 8); // read 8 bytes from infile and store them in buffer[]

	// if read() reaches end of file, it sets both eof and failbit flags
	if (infile.fail() && !infile.eof()) { cout << "\nError while reading from <infile>. Exiting DES."; exit(0); }

	// if end of file reached, fill the remaining bytes in buffer[] with random garbage
	if (infile.eof()) for (int i = (int)infile.gcount(); i < 8; ++i) buffer[i] = 0;

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
	for (int i = 0; i < 8; ++i) {
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