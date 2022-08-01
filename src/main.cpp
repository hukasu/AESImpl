#include <aes_lib.hpp>

#include <iostream>
#include <sstream>
#include <fstream>
#include <filesystem>

void printHelp(char* path) {
	std::cout << path << " <mode> <input> <output> <key>" << std::endl;
	std::cout << "\tmode\t\tEncrypt or decrypt mode" << std::endl;
	std::cout << "\tinput\t\tInput file" << std::endl;
	std::cout << "\toutput\t\tOutput file" << std::endl;
	std::cout << "\tkey\t\tEncryption/decryption key in hex" << std::endl;
	std::cout << "Modes:" << std::endl;
	std::cout << "\t-d, --decrypt\tDecrypts a file" << std::endl;
	std::cout << "\t-e, --encrypt\tEncrypts a file" << std::endl;
}

int main(int argc, char** argv) {
	if (argc == 1 || (argc == 2 && std::strcmp(argv[1], "--help") == 0)) {
		printHelp(argv[0]);
		return 0;
	} else if (argc != 5) {
		std::cerr << "Incorrent number of arguments." << std::endl;
		printHelp(argv[0]);
		return 1;
	} else if (std::strcmp(argv[1], "-d") && std::strcmp(argv[1], "--decrypt") && std::strcmp(argv[1], "-e") && std::strcmp(argv[1], "--encrypt")) {
		// std::strcmp returns zero on equal strings, so a single zero result is due to valid mode
		std::cerr << "Invalid mode." << std::endl;
		printHelp(argv[0]);
		return 1;
	}

	std::filesystem::path input_file_path(argv[2]);
	if (!std::filesystem::exists(input_file_path)) {
		std::cerr << "Input file does not exist." << std::endl;
		return 1;
	}
	std::filesystem::path output_file_path(argv[3]);
	if (std::filesystem::exists(output_file_path)) {
		std::cout << "Output file " << output_file_path << " already exists, should replace? (y/N)" << std::endl;
		char o;
		std::cin >> o;
		if (o == 'y' || o == 'Y') {
			std::cout << "Replacing file " << output_file_path << std::endl;
		} else {
			return 0;
		}
	}
	std::stringstream key_reader;
	key_reader << std::hex << argv[4];
	std::string key_str;
	key_reader >> key_str;

	if (key_str.length() != 128 && key_str.length() != 192 && key_str.length() != 256) {
		std::cerr << "Key of invalid size. Must be 128, 192, or 256 bit long." << std::endl;
	}

	std::ifstream input_file(input_file_path, std::ios::in | std::ios::binary);
	std::ofstream output_file(output_file_path, std::ios::out | std::ios::binary);

	return 0;
}