#ifndef PARSER_HPP
#define PARSER_HPP

#include <string>

#include "crypto_file.hpp"

namespace parser
{
	std::optional<crypto_file> parse(const std::string& file_name);
	
	std::optional<crypto_file> parse(std::istream& stream);
};

#endif // PARSER_HPP
