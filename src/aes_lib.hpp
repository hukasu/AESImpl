#ifndef __AES__LIB__HPP__
#define __AES__LIB__HPP__

#include <cstdlib>
#include <string>
#include <array>

namespace aes {
	typedef std::array<uint8_t, 4> PolynomialWord;
	typedef std::array<uint8_t, 128> BlockType;

	typedef std::array<uint8_t, 128> Key128Type;
	typedef std::array<uint8_t, 192> Key192Type;
	typedef std::array<uint8_t, 256> Key256Type;

	BlockType encrypt(BlockType* _block, Key128Type* _key);
	BlockType encrypt(BlockType* _block, Key192Type* _key);
	BlockType encrypt(BlockType* _block, Key256Type* _key);

	BlockType decrypt(BlockType* _block, Key128Type* _key);
	BlockType decrypt(BlockType* _block, Key192Type* _key);
	BlockType decrypt(BlockType* _block, Key256Type* _key);
}

#endif // __AES__LIB__HPP__