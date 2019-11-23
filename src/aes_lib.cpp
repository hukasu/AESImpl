﻿#include "aes_lib.hpp"

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

	inline uint8_t gfAddition(uint8_t _lhs, uint8_t _rhs) {
		return _lhs ^ _rhs;
	}

	inline uint8_t gfMultiplication(uint8_t _lhs, uint8_t _rhs) {
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

	void byteSubstitution(BlockType* _block) {
		for (uint8_t i = 0; i < 128; i++) {
			(*_block)[i] = rijndael_substitution_box[(*_block)[i]];
		}
	}

	void shiftRows(BlockType* _block) {
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

	void mixCollumn(BlockType* _block) {
		PolynomialWord cx = {
			0x03, 0x01, 0x01, 0x02
		};
		PolynomialWord temp;
		// Collumn 0
		temp = gfMultiplication(
			PolynomialWord{
				(*_block)[0],
				(*_block)[1],
				(*_block)[2],
				(*_block)[3]
			},
			cx
		);
		(*_block)[0] = temp[0];
		(*_block)[1] = temp[1];
		(*_block)[2] = temp[2];
		(*_block)[3] = temp[3];
		// Collumn 1
		temp = gfMultiplication(
			PolynomialWord{
				(*_block)[4],
				(*_block)[5],
				(*_block)[6],
				(*_block)[7]
			},
			cx
		);
		(*_block)[4] = temp[0];
		(*_block)[5] = temp[1];
		(*_block)[6] = temp[2];
		(*_block)[7] = temp[3];
		// Collumn 2
		temp = gfMultiplication(
			PolynomialWord{
				(*_block)[8],
				(*_block)[9],
				(*_block)[10],
				(*_block)[11]
			},
			cx
		);
		(*_block)[8] = temp[0];
		(*_block)[9] = temp[1];
		(*_block)[10] = temp[2];
		(*_block)[11] = temp[3];
		// Collumn 3
		temp = gfMultiplication(
			PolynomialWord{
				(*_block)[12],
				(*_block)[13],
				(*_block)[14],
				(*_block)[15]
			},
			cx
		);
		(*_block)[12] = temp[0];
		(*_block)[13] = temp[1];
		(*_block)[14] = temp[2];
		(*_block)[15] = temp[3];
	}

	template<int key_size>
	void addRoundKey(BlockType* _block, std::array<uint8_t, key_size>* _key) {

	}

	template<int key_size>
	void round(BlockType* _block, std::array<uint8_t, key_size>* _key, bool final_round = false) {
		byteSubstitution(_block);
		shiftRows(_block);
		if (!final_round) mixCollumn(_block);
		addRoundKey(_block, _key);
	}

	template<int key_size>
	void keyExpansion() {

	}

	BlockType encrypt(BlockType* _block, Key128Type* _key) {
		for (uint8_t i = 0; i < 9; i++) {
			round(_block, _key);
		}
		round(_block, _key, true);
		return BlockType{};
	}

	BlockType encrypt(BlockType* _block, Key192Type* _key) {
		for (uint8_t i = 0; i < 11; i++) {
			round(_block, _key);
		}
		round(_block, _key, true);
		return BlockType{};
	}

	BlockType encrypt(BlockType* _block, Key256Type* _key) {
		for (uint8_t i = 0; i < 13; i++) {
			round(_block, _key);
		}
		round(_block, _key, true);
		return BlockType{};
	}

	BlockType decrypt(BlockType* _block, Key128Type* _key) {
		return BlockType{};
	}

	BlockType decrypt(BlockType* _block, Key192Type* _key) {
		return BlockType{};
	}

	BlockType decrypt(BlockType* _block, Key256Type* _key) {
		return BlockType{};
	}
}