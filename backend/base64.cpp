#include "base64.h"


safe_string b64_encode(const safe_vector<byte>& input)
{
	return b64_encode(input.data(), input.size());
}

safe_string b64_encode(const byte * input, std::size_t size)
{
	const std::size_t exp_out_size =  4 * ((size + 2) / 3) + 1;
	char * encoded = new char[exp_out_size];
	
	const int out_size = EVP_EncodeBlock(reinterpret_cast<byte *>(encoded), input, size);
	if(exp_out_size - 1 != out_size) throw std::length_error("Error while trying to encode block of data into b64; the expected and output sizes do not match!\n");
	return safe_string(encoded);
}

safe_vector<byte> b64_decode(const safe_string& input)
{
	return b64_decode(reinterpret_cast<const byte*>(input.c_str()), input.length());
}

//safe_vector<byte> b64_decode(const char * encoded, std::size_t size)
//{
//	return b64_decode(reinterpret_cast<const byte *>(encoded), size);
//}

safe_vector<byte> b64_decode(const byte * input, std::size_t size)
{
	if(size % 4) throw std::length_error("Given invalid b64 data size to decode!\n");
	const std::size_t exp_out_size = (size / 4) * 3;
	safe_vector<byte> decoded(exp_out_size);
	
	int out_size = EVP_DecodeBlock(decoded.data(), input, size);
	if(exp_out_size != out_size) throw std::length_error("Error while trying to decode block of data from b64; the expceted and decoded sizes do not match!\n");
	for(int i = out_size - 1; i > 0; --i)
	{
		if(decoded[i] == '\0') out_size = i;
		else break;
	}
	decoded.resize(out_size);
	return decoded;
}