#ifndef CRYPTO_FILE_HPP
#define CRYPTO_FILE_HPP

#include <string>
#include <vector>
#include <utility>
#include <ostream>
#include <unordered_map>

#include "openssl_types_util.hpp"



struct crypto_file
{
	
	
	safe_string description;
	safe_string file_name;
	safe_vector<std::pair<safe_string, int>> methods;
	safe_vector<byte> secret_key;
//	safe_vector<byte> iv;
	safe_vector<byte> iv;
	safe_vector<byte> N;
	safe_vector<byte> e;
	safe_vector<byte> d;
	safe_vector<byte> data;
	safe_vector<byte> envelope_data;
	safe_vector<byte> env_key;
	safe_vector<byte> signature;
	
};

//std::istream& operator>>(std::istream&, crypto_file);

std::ostream& operator<<(std::ostream&, const crypto_file&);

#endif // CRYPTO_FILE_HPP
