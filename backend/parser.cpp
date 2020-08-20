#include "parser.hpp"
#include "openssl_types_util.hpp"
#include "base64.h"

#include <openssl/evp.h>

#include <unordered_map>
#include <fstream>
#include <iostream>
#include <string_view>
#include <regex>
#include <sstream>
#include <optional>


static void parse_description(std::istream& stream, crypto_file& cfile)
{
	if(!stream.good()) throw std::runtime_error("Error while trying to parse description property of file");
	std::getline(stream >> std::ws, cfile.description);
}

static void parse_file_name(std::istream& stream, crypto_file& cfile)
{
	if(!stream.good()) throw std::runtime_error("Error on stream while trying to parse 'Filename' property");
	std::getline(stream >> std::ws, cfile.file_name);
}

static void parse_methods(std::istream& stream, crypto_file& cfile)
{
	safe_string line{};
	char peeked = stream.peek();
	while((peeked == ' ' || peeked == '\t') && std::getline(stream >> std::ws, line))
	{
		if(line.empty() || line[0] == ' ' || line[0] == '\t') break;
		
		cfile.methods.emplace_back(std::move(line), -1);
		
		peeked = stream.peek();
	}
}

static void parse_key_lengths(std::istream& stream, crypto_file& cfile)
{
	safe_string line{};
	int i = 0;
	int key_size = -1;
	char peeked = stream.peek();
	while((peeked == ' ' || peeked == '\t') && std::getline(stream >> std::ws, line))
	{
		if(line.empty()) break;
		
		if(sscanf(line.c_str(), "%x", &key_size))
		{
			cfile.methods[i++].second = key_size;
		}
		peeked = stream.peek();
	}
}

static safe_vector<byte> parse_hex_data(std::istream& stream)
{
	safe_stringstream data_stream{};
	safe_string line{};
	size_t length = 0;
	char peeked = stream.peek();
	while((peeked == ' ' || peeked == '\t') && std::getline(stream >> std::ws, line))
	{
		if(line.empty()) break;
		length += line.length();
		data_stream << line;
		
		peeked = stream.peek();
	}
	
	safe_vector<byte> result(length / 2);
	auto hex_str = std::move(data_stream.str());
	for(size_t i = 0; i < length / 2; ++i)
	{
		sscanf(hex_str.c_str() + i * 2, "%02hhX", result.data() + i);
	}

	
	return result;
}

static safe_vector<byte> parse_b64_data(std::istream& stream)
{
	safe_stringstream data_stream{};
	safe_string data;
	size_t length = 0;
	char peeked = stream.peek();
	while((peeked == ' ' || peeked == '\t') && std::getline(stream >> std::ws, data))
	{
		if(data.empty()) break;
		length += data.length();
		data_stream << data;
		
		peeked = stream.peek();
	}
	data = data_stream.str();
	
	return b64_decode(data);
}

static void parse_secret_key(std::istream& stream, crypto_file& cfile)
{
	cfile.secret_key = parse_hex_data(stream);
}

static void parse_iv(std::istream& stream, crypto_file& cfile)
{
	cfile.iv = parse_hex_data(stream);
//	if(!stream.good()) throw std::runtime_error("Cannot parse 'Initialization vector' because the stream is not valid anymore");
//	std::getline(stream >> std::ws, cfile.iv);
}

static void parse_modulus(std::istream& stream, crypto_file& cfile)
{
	cfile.N = parse_hex_data(stream);
}

static void parse_e(std::istream& stream, crypto_file& cfile)
{
	cfile.e = parse_hex_data(stream);
}

static void parse_d(std::istream& stream, crypto_file& cfile)
{
	cfile.d = parse_hex_data(stream);
}

static void parse_signature(std::istream& stream, crypto_file& cfile)
{
	cfile.signature = parse_hex_data(stream);
}

static void parse_data(std::istream& stream, crypto_file& cfile)
{
	cfile.data = parse_b64_data(stream);
}

static void parse_env_data(std::istream& stream, crypto_file& cfile)
{
	cfile.envelope_data = parse_b64_data(stream);
}

static void parse_env_key(std::istream& stream, crypto_file& cfile)
{
	cfile.env_key = parse_hex_data(stream);
}

using svmatch = std::match_results<std::string_view::const_iterator>;

static void process_file(std::istream& file, crypto_file& crypt_file)
{
//	static constexpr std::string_view BEGIN = "---BEGIN OS2 CRYPTO DATA---";
//	static constexpr std::string_view END   = "---END OS2 CRYPTO DATA---";
	static const std::regex begin_rgx{"\\s*-{0,4}\\s*BEGIN\\s*NOS\\s*CRYPTO\\s*DATA\\s*-{0,4}", std::regex::optimize};
	static const std::regex end_rgx{"\\s*-{0,4}\\s*END\\s*NOS\\s*CRYPTO\\s*DATA\\s*-{0,4}", std::regex::optimize};
	static const std::regex prop_rgx{"([a-zA-Z\\s]+):", std::regex::optimize};

	using parse_function = decltype(&parse_description);
	static std::unordered_map<std::string_view, parse_function> parse_map{
																			{"Description", &parse_description},
																			{"File name", &parse_file_name},
																			{"Method", &parse_methods},
																			{"Key length", &parse_key_lengths},
																			{"Secret key", &parse_secret_key},
																			{"Initialization vector", &parse_iv},
																			{"Modulus", &parse_modulus},
																			{"Public exponent", &parse_e},
																			{"Private exponent", &parse_d},
																			{"Signature", &parse_signature},
																			{"Data", &parse_data},
																			{"Envelope data", &parse_env_data},
																			{"Envelope crypt key", &parse_env_key}
																	     };
	
	std::string line;
	
	while(std::getline(file, line))
	{
		if(line.empty()) continue;
		if(std::regex_match(line, begin_rgx)) break;
	}
	
	using svmatch = std::match_results<std::string_view::const_iterator>;
	
	svmatch m;
	while(std::getline(file, line))
	{
		if(line.empty()) continue;
		
		if(std::regex_match(line, end_rgx)) break;
		
		std::string_view line_view(line);
		if(std::regex_match(line_view.cbegin(), line_view.cend(), m, prop_rgx))
		{
			std::string_view property{&*m[1].first, m[1].second - m[1].first};
			parse_map[property](file, crypt_file);
		}
		
	}
}

namespace parser
{
	std::optional<crypto_file> parse(const std::string& file_name)
	{
		std::ifstream file(file_name);
		
		if(!file.good())
		{
			std::cerr << "Parser: error while trying to open file: " << file_name << '\n';
			return std::nullopt;
		}
		
		return parse(file);
	}
	
	std::optional<crypto_file> parse(std::istream& stream)
	{
		if(!stream.good())
		{
			std::cerr << "Parser: given stream is bad!\n";
			return std::nullopt;
		}
		
		crypto_file cfile{};
		process_file(stream, cfile);
		return {cfile};
	}
};


