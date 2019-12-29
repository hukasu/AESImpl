#include <iostream>
#include <sstream>
#include <iomanip>

#include "../src/aes_lib.cpp"

template <uint8_t key_size>
uint8_t doTest(std::string& _key, std::string& _expanded_key) {
	constexpr uint8_t round_count = aes::getRoundCount<4, key_size>();
	std::array<uint8_t, 4 * key_size> key;
	std::array<uint8_t, 4 * 4 * (round_count + 1)> expanded_key, result_key;
	std::memcpy(key.data(), _key.data(), 4 * key_size);
	std::memcpy(result_key.data(), _expanded_key.data(), 4 * 4 * (round_count + 1));
	expanded_key = aes::keyExpansion<4 * (round_count + 1), key_size>(&key);
	return result_key != expanded_key;
}

int main(int argc, char** argv) {
	std::string
		key(aes::fromHexStringToBits(std::string(argv[1]))),
		result(aes::fromHexStringToBits(std::string(argv[2])));

	if (key.size() / 4 == 4) return doTest<4>(key, result);
	else if (key.size() / 4 == 6) return doTest<6>(key, result);
	else if (key.size() / 4 == 8) return doTest<8>(key, result);

	return -1;
}