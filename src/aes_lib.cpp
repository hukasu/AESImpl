﻿#include "aes_lib.hpp"

#include <sstream>
#include <iomanip>

namespace aes {
	std::array<uint8_t, 0x100> rijndael_substitution_box = {
		0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
		0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
		0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
		0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
		0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
		0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
		0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
		0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
		0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
		0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
		0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
		0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
		0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
		0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
		0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
		0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16
	};

	constexpr uint8_t getRoundCount(uint8_t block_size, uint8_t key_size) {
		return block_size == 16 ? (key_size == 16 ? 10 : (key_size == 24 ? 12 : 14)) : (block_size == 24 ? (key_size == 32 ? 14 : 12) : 14);
	}
	static_assert(getRoundCount(16, 16) == 10);
	static_assert(getRoundCount(16, 24) == 12);
	static_assert(getRoundCount(16, 32) == 14);
	static_assert(getRoundCount(24, 16) == 12);
	static_assert(getRoundCount(24, 24) == 12);
	static_assert(getRoundCount(24, 32) == 14);
	static_assert(getRoundCount(32, 16) == 14);
	static_assert(getRoundCount(32, 24) == 14);
	static_assert(getRoundCount(32, 32) == 14);

	constexpr inline uint8_t gfAddition(uint8_t _lhs, uint8_t _rhs) {
		return _lhs ^ _rhs;
	}
	static_assert(gfAddition(0x57, 0x83) == 0xd4);

	constexpr inline uint8_t gfMultiplication(uint8_t _lhs, uint8_t _rhs) {
		uint16_t temp = 0;
		uint8_t index = 8;
		while (index-- > 0) {
			uint8_t mask = 1 << index;
			if (_rhs & mask) {
				temp ^= (_lhs << index);
			}
		}
		index = 16;
		while (index-- > 8) {
			uint16_t mask = 1 << index;
			if (temp & mask) {
				temp ^= (0x11b << (index - 8));
			}
		}
		return static_cast<uint8_t>(temp);
	}
	static_assert(gfMultiplication(0x57, 0x83) == 0xc1);
	static_assert(gfMultiplication(0x57, 0x13) == 0xfe);
	static_assert(gfMultiplication(0x57, 0x02) == 0xae);
	static_assert(gfMultiplication(0x57, 0x04) == 0x47);
	static_assert(gfMultiplication(0xae, 0x02) == 0x47);
	static_assert(gfMultiplication(0x57, 0x08) == 0x8e);
	static_assert(gfMultiplication(0x47, 0x02) == 0x8e);
	static_assert(gfMultiplication(0x57, 0x10) == 0x07);
	static_assert(gfMultiplication(0x8e, 0x02) == 0x07);
	static_assert(gfMultiplication(0x57, gfAddition(gfAddition(0x01, 0x02), 0x10)) == gfMultiplication(0x57, 0x13));

	inline PolynomialWord gfAddition(PolynomialWord _lhs, PolynomialWord _rhs) {
		return PolynomialWord{
			gfAddition(_lhs[0], _rhs[0]),
			gfAddition(_lhs[1], _rhs[1]),
			gfAddition(_lhs[2], _rhs[2]),
			gfAddition(_lhs[3], _rhs[3]),
		};
	}

	inline PolynomialWord gfMultiplication(PolynomialWord _lhs, PolynomialWord _rhs) {
		return PolynomialWord{
			gfAddition(
				gfAddition(
					gfMultiplication(_lhs[0], _rhs[0]),
					gfMultiplication(_lhs[3], _rhs[1])
				),
				gfAddition(
					gfMultiplication(_lhs[2], _rhs[2]),
					gfMultiplication(_lhs[1], _rhs[3])
				)
			),
			gfAddition(
				gfAddition(
					gfMultiplication(_lhs[1], _rhs[0]),
					gfMultiplication(_lhs[0], _rhs[1])
				),
				gfAddition(
					gfMultiplication(_lhs[3], _rhs[2]),
					gfMultiplication(_lhs[2], _rhs[3])
				)
			),
			gfAddition(
				gfAddition(
					gfMultiplication(_lhs[2], _rhs[0]),
					gfMultiplication(_lhs[1], _rhs[1])
				),
				gfAddition(
					gfMultiplication(_lhs[0], _rhs[2]),
					gfMultiplication(_lhs[3], _rhs[3])
				)
			),
			gfAddition(
				gfAddition(
					gfMultiplication(_lhs[3], _rhs[0]),
					gfMultiplication(_lhs[2], _rhs[1])
				),
				gfAddition(
					gfMultiplication(_lhs[1], _rhs[2]),
					gfMultiplication(_lhs[0], _rhs[3])
				)
			)
		};
	}

	template<uint8_t block_size>
	void byteSubstitution(std::array<uint8_t, block_size>* _block) {
		for (uint8_t i = 0; i < block_size; i++) {
			(*_block)[i] = rijndael_substitution_box[(*_block)[i]];
		}
	}

	template<uint8_t block_size>
	void shiftRows(std::array<uint8_t, block_size>* _block) {
		// Row 0 does nothing
		// Row 1 shift by 1
		std::swap((*_block)[1], (*_block)[5]);
		std::swap((*_block)[5], (*_block)[9]);
		std::swap((*_block)[9], (*_block)[13]);
		// Row 2 shift by 2
		std::swap((*_block)[2], (*_block)[10]);
		std::swap((*_block)[6], (*_block)[14]);
		// Row 3 shift by 3
		std::swap((*_block)[15], (*_block)[11]);
		std::swap((*_block)[11], (*_block)[7]);
		std::swap((*_block)[7], (*_block)[3]);
	}

	template<uint8_t block_size>
	void mixColumns(std::array<uint8_t, block_size>* _block) {
		PolynomialWord cx = {
			0x03, 0x01, 0x01, 0x02
		};
		for (uint64_t i = 0; i < (block_size / 4); i++) {
			PolynomialWord temp = gfMultiplication(
				cx,
				PolynomialWord{
					(*_block)[i + 0],
					(*_block)[i + 1],
					(*_block)[i + 2],
					(*_block)[i + 3]
				}
			);
			(*_block)[i + 0] = temp[0];
			(*_block)[i + 1] = temp[1];
			(*_block)[i + 2] = temp[2];
			(*_block)[i + 3] = temp[3];
		}
	}

	template<uint8_t block_size>
	void addRoundKey(std::array<uint8_t, block_size>* _block, std::array<uint8_t, block_size>* _key) {
		for (uint8_t i = 0; i < block_size; i++) {
			(*_block)[i] = gfAddition((*_block)[i], (*_key)[i]);
		}
	}

	template<uint8_t block_size>
	void round(std::array<uint8_t, block_size>* _block, std::array<uint8_t, block_size>* _key, bool final_round = false) {
		byteSubstitution(_block);
		shiftRows(_block);
		if (!final_round) mixColumns(_block);
		addRoundKey(_block, _key);
	}

	PolynomialWord substituteWord(PolynomialWord _word) {
		return PolynomialWord{
			rijndael_substitution_box[_word[0]],
			rijndael_substitution_box[_word[1]],
			rijndael_substitution_box[_word[2]],
			rijndael_substitution_box[_word[3]]
		};
	}

	PolynomialWord rotateWord(PolynomialWord _word) {
		return PolynomialWord{
			_word[1],
			_word[2],
			_word[3],
			_word[0],
		};
	}

	template<uint32_t expanded_key_size, uint8_t key_size>
	std::array<uint8_t, expanded_key_size> keyExpansion(std::array<uint8_t, key_size>* _key) {
		std::array<uint8_t, expanded_key_size> expanded_key;

		std::memcpy(expanded_key.data(), _key->data(), key_size);

		PolynomialWord round_constant = { 0x01, 0x00, 0x00, 0x00 };
		for (uint64_t i = key_size; i < expanded_key_size; i += 4) {
			PolynomialWord temp;

			std::memcpy(temp.data(), expanded_key.data() + i, 4);
			if constexpr (key_size == 32) {
				if (i % (key_size) == 4) {
					temp = substituteWord(temp);
				}
			} else {
				if (i % (key_size / 4) == 0) {
					temp = gfAddition(substituteWord(rotateWord(temp)), round_constant);
				}
			}

			expanded_key[i + 0] = gfAddition(temp[0], expanded_key[i - (key_size / 4)]);
			expanded_key[i + 1] = gfAddition(temp[1], expanded_key[i - (key_size / 4)]);
			expanded_key[i + 2] = gfAddition(temp[2], expanded_key[i - (key_size / 4)]);
			expanded_key[i + 3] = gfAddition(temp[3], expanded_key[i - (key_size / 4)]);

			round_constant = PolynomialWord{
				gfMultiplication(round_constant[0], 0x02),
				0x00,
				0x00,
				0x00
			};
		}

		return std::move(expanded_key);
	}

	template<uint8_t key_size>
	std::array<uint8_t, key_size> prepareKey(std::istream& _key) {
		std::array<uint8_t, key_size> key;
		_key.read(reinterpret_cast<char*>(key.data()), key_size);
		return key;
	}

	template<uint8_t block_size, uint8_t key_size>
	inline void _encryptBlock(
		std::array<uint8_t, block_size>* _block,
		std::array<uint8_t, key_size>* _key
	) {
		constexpr uint8_t rounds = getRoundCount(block_size, key_size);

		std::array<uint8_t, block_size> round_key;
		std::array<uint8_t, block_size * (rounds + 1)> expanded_key = keyExpansion<block_size * (rounds + 1)>(_key);

		std::memcpy(round_key.data(), expanded_key.data(), block_size);
		addRoundKey(_block, &round_key);

		for (uint64_t i = 1; i < (rounds - 1); i++) {
			std::memcpy(round_key.data(), expanded_key.data() + (i * block_size), block_size);
			round(_block, &round_key);
		}

		std::memcpy(round_key.data(), expanded_key.data() + (rounds * block_size), block_size);
		round(_block, &round_key, true);
	}

	template<uint8_t key_size>
	void _encrypt(std::istream& _input_data, std::ostream& _output_cypher, std::istream& _key) {
		std::array<uint8_t, key_size> key = prepareKey<key_size>(_key);

		do {
			BlockType data;
			size_t read = _input_data.readsome(reinterpret_cast<char*>(data.data()), 16);
			if (read != 16) {
				if (_input_data.eof()) {
					for (uint8_t i = static_cast<uint8_t>(read); i < 16; i++) {
						data[i] = 0;
					}
				} else std::runtime_error("Internal error: didn't read enough caracters. (0x01)");
			}
			_encryptBlock(&data, &key);
			_output_cypher.write(reinterpret_cast<char*>(data.data()), 16);
		} while (!_input_data.eof());
	}

	void encrypt(std::istream& _input_data, std::ostream& _output_cypher, std::istream& _key) {
		std::streampos key_size;
		_key.seekg(0, std::ios::end);
		key_size = _key.tellg();
		_key.seekg(0, std::ios::beg);

		if (key_size == 16) _encrypt<16>(_input_data, _output_cypher, _key);
		else if (key_size == 24) _encrypt<24>(_input_data, _output_cypher, _key);
		else if (key_size == 32) _encrypt<32>(_input_data, _output_cypher, _key);
		else throw std::runtime_error("Key must have 128, 192, or 256 bits.");
	}

	template<uint8_t block_size, uint8_t key_size>
	inline void _decryptBlock(
		std::array<uint8_t, block_size>* _block,
		std::array<uint8_t, key_size>* _key
	) {

	}

	template<uint8_t key_size>
	void _decrypt(std::istream& _input_cypher, std::ostream& _output_data, std::istream& _key) {
		std::array<uint8_t, key_size> key = prepareKey<key_size>(_key);

		do {
			BlockType cypher;
			size_t read = _input_cypher.readsome(reinterpret_cast<char*>(cypher.data()), 16);
			if (read != 16) std::runtime_error("Internal error: didn't read enough caracters. (0x02)");
			_decryptBlock(&cypher, &key);
			uint8_t writing = 16;
			if (_input_cypher.eof()) {
				for (uint8_t i = 15; i > 0; i--) {
					if (cypher[i] == 0 && cypher[i - 1] != 0) writing--;
				}
			}
			_output_data.write(reinterpret_cast<char*>(cypher.data()), writing);
		} while (!_input_cypher.eof());
	}

	void decrypt(std::istream& _input_cypher, std::ostream& _output_data, std::istream& _key) {
		std::streampos key_size;
		_key.seekg(0, std::ios::end);
		key_size = _key.tellg();
		_key.seekg(0, std::ios::beg);

		if (key_size == 16) _decrypt<16>(_input_cypher, _output_data, _key);
		else if (key_size == 24) _decrypt<24>(_input_cypher, _output_data, _key);
		else if (key_size == 32) _decrypt<32>(_input_cypher, _output_data, _key);
		else throw std::runtime_error("Key must have 128, 192, or 256 bits.");
	}

	std::string fromHexStringToBits(std::string _input) {
		std::stringstream input_ss(std::ios::in | std::ios::out | std::ios::binary), output_ss(std::ios::in | std::ios::out | std::ios::binary);
		input_ss << _input;
		char hex[2];
		while (!input_ss.read(hex, 2).eof()) {
			size_t l;
			char c = static_cast<char>(std::stoi(hex, &l, 16));
			if (l != 2) throw std::runtime_error("Converter encountered a invalid hex value.");
			else output_ss << static_cast<char>(std::stoi(hex, nullptr, 16));
		}
		return output_ss.str();
	}

	std::string fromBitsToHexString(std::string _input) {
		std::stringstream input_ss(std::ios::in | std::ios::out | std::ios::binary), output_ss(std::ios::in | std::ios::out | std::ios::binary);
		input_ss << _input;
		char hex[2];
		hex[1] = '\x0';
		while (!input_ss.read(hex, 1).eof()) {
			output_ss << std::hex << std::setw(2) << std::setfill('0') << static_cast<uint64_t>(hex[0]);
		}
		return output_ss.str();
	}
}