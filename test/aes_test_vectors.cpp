#include <aes_lib.hpp>

#include <iostream>
#include <sstream>

int main(int argc, char** argv) {
	std::string 
		data(aes::fromHexStringToBits(std::string(argv[1]))),
		result(aes::fromHexStringToBits(std::string(argv[2]))),
		key(aes::fromHexStringToBits(std::string(argv[3])));

	std::istringstream data_stream(data, std::ios::in | std::ios::binary);
	std::ostringstream cypher_stream(std::ios::out | std::ios::binary);
	std::istringstream key_stream(key, std::ios::in | std::ios::binary);

	aes::encrypt(data_stream, cypher_stream, key_stream);

	std::string cypher = cypher_stream.str();

	if (cypher.compare(result)) return -1;

	std::istringstream inv_data_stream(cypher, std::ios::in | std::ios::binary);
	std::ostringstream inv_cypher_stream(std::ios::out | std::ios::binary);

	aes::decrypt(inv_data_stream, inv_cypher_stream, key_stream);

	std::string inv_cypher = inv_cypher_stream.str();

	if (inv_cypher.compare(data)) return -1;
	
	return 0;
}