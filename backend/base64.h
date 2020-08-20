#ifndef BASE64_H
#define BASE64_H

#include "openssl_types_util.hpp"

#include <openssl/evp.h>
#include <stdexcept>
#include <string>

safe_string b64_encode(const safe_vector<byte>&);

safe_string b64_encode(const byte *, std::size_t);

safe_vector<byte> b64_decode(const safe_string&);

safe_vector<byte> b64_decode(const byte*, std::size_t);

//using byte = unsigned char;
//
//
//template<typename T>
//static byte * reinterpret(const T* ptr)
//{
//	return reinterpret_cast<byte *>(ptr);
//}
//
//static byte * reinterpret(const byte* ptr)
//{
//	return ptr;
//}
//
//template<typename InputStorage, typename OutputStorage>
//OutputStorage b64_encode(const InputStorage& input)
//{
//	const size_t exp_out_size =  4 * ((input.size() + 2) / 3) + 1;
//	OutputStorage output{exp_out_size};
//	const int out_size = EVP_EncodeBlock(reinterpret(&output[0])), reinterpret(&input[0]), input.size());
//	if(exp_out_size - 1 != out_size) throw std::length_error("Error while trying to encode block of data into b64; the expected and output sizes do not match!\n");
//	return output;
//	
//}
//
//
//template<typename Input, typename Output>
//Output b64_decode(const Input& encoded)
//{
//	const size_t exp_out_size = (encoded.size() / 4) * 3 + 1;
//	Output output{exp_out_size};
//	const int out_size = EVP_DecodeBlock(reinterpret(&output[0]), reinterpret(&encoded[0]), encoded.size());
//	if(exp_out_size - 1 != out_size) throw std::length_error("Error while trying to decode block of data from b64; The expected and output sizes do not match!\n");
//	return output;
//}






#endif