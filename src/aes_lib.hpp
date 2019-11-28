#ifndef __AES__LIB__HPP__
#define __AES__LIB__HPP__

#include <cstdlib>
#include <string>
#include <array>

namespace aes {
	typedef std::array<uint8_t, 4> PolynomialWord;
	typedef std::array<uint8_t, 16> BlockType;

	typedef std::array<uint8_t, 16> Key128Type;
	typedef std::array<uint8_t, 24> Key192Type;
	typedef std::array<uint8_t, 32> Key256Type;

	void encrypt(std::istream& _input_data, std::ostream& _output_cypher, std::istream& _key);
	void decrypt(std::istream& _input_cypher, std::ostream& _output_data, std::istream& _key);

	// Translates a string of hex values into a string of bits
	// i.e. "0001" into "\\x0\\x1"
	std::string fromHexStringToBits(std::string _str);

	// Translates a string into a string  of hex values
	// i.e. "\\x0\\x1" into "0001"
	std::string fromBitsToHexString(std::string _str);
}

#endif // __AES__LIB__HPP__