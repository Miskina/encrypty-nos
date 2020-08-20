#include "crypto_file.hpp"
#include "base64.h"
#include "utils.hpp"

#include <string_view>
#include <iomanip>

static void output_hex(std::ostream& stream, const safe_vector<byte>& bytes, const std::string_view output)
{
	
	stream << output;
	for(size_t i = 0, n = bytes.size(); i < n; ++i)
	{
		if(!(i % 60))
		{
			stream << "\n\t";
		}
		stream << std::setw(2) << std::setfill('0') << std::hex << (int)bytes[i];
	}
	stream << '\n';
}

static void output_b64(std::ostream& stream, const safe_string& output, const std::string_view name)
{
	stream << name;
	auto ptr = &output[0];
	size_t size = utils::min(std::size_t{60}, output.size());
	size_t processed = 0;
	while(processed < output.size())
	{
		std::string_view sv(ptr, size);
		stream << "\n\t" << sv;
		ptr += size;
		processed += size;
		size = utils::min(std::size_t{60}, output.size() - processed);
	}
	stream << '\n';
}

std::ostream& operator<<(std::ostream& stream, const crypto_file& cf)
{
	stream << "---BEGIN NOS CRYPTO DATA---\n\n";
	
	stream << "Description:\n\t" << cf.description << '\n';
	
	if(!cf.file_name.empty())
	{
		stream << "\nFile name:\n\t" << cf.file_name << '\n';
	}
	
	if(!cf.methods.empty())
	{
		stream << "\nMethod:\n";
		for(const auto&[method, key_length] : cf.methods)
		{
			stream << '\t' << method << '\n';
		}
		
		bool key_length_written = false;
		for(const auto&[method, key_length] : cf.methods)
		{
			if(key_length != -1)
			{
				if(!key_length_written)
				{
					stream << "\nKey length:\n";
					key_length_written = true;
				}
				
				stream << '\t' << std::setw(4) << std::setfill('0') << std::hex << key_length << '\n';
			}
		}
	}
	
	if(!cf.secret_key.empty())
	{
//		stream << "\nSecret key:";
		output_hex(stream, cf.secret_key, "\nSecret key:");
	}
	
	if(!cf.iv.empty())
	{
//		stream << "\nInitialization vector:\n\t" << cf.iv << '\n';;
		output_hex(stream, cf.iv, "\nInitialization vector:");
	}
	
	if(!cf.N.empty())
	{
//		stream << "\nModulus:";
		output_hex(stream, cf.N, "\nModulus:");
	}
	
	if(!cf.e.empty())
	{
//		stream << "\nPublic exponent:";
		output_hex(stream, cf.e, "\nPublic exponent:");
	}
	
	if(!cf.d.empty())
	{
//		stream << "\nPrivate exponent:";
		output_hex(stream, cf.d, "\nPrivate exponent:");
	}
	
	if(!cf.signature.empty())
	{
		output_hex(stream, cf.signature, "\nSignature:");
	}
	
	if(!cf.data.empty())
	{
		const auto encoded_data = b64_encode(cf.data);
		output_b64(stream, encoded_data, "\nData:");
	}
	
	if(!cf.envelope_data.empty())
	{
		const auto encoded_data = b64_encode(cf.envelope_data);
		output_b64(stream, encoded_data, "\nEnvelope data:");
	}
	
	if(!cf.env_key.empty())
	{
		output_hex(stream, cf.env_key, "\nEnvelope crypt key:");
	}
	
	
	stream << "\n\n---END NOS CRPYTO DATA---\n" << std::flush;
	return stream;
}

