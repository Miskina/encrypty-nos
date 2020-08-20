#include "encrypt.hpp"

#include <stdexcept>

#include <openssl/rand.h>

namespace crypt
{

	void random_byte_fill(byte * data, const std::size_t len)
	{
		if(!RAND_bytes(data, len))
		{
			throw std::runtime_error("Error while filling data with random bytes using RAND_bytes\n");
		}
	}
	
	
	safe_vector<byte> symmetric_encrypt(const byte * data, const std::size_t data_len,
										const byte * key, const std::size_t key_len,
										const byte * iv, const std::size_t iv_len,
										const EVP_CIPHER * cipher)
	{
		EVP_CIPHER_CTX * ctx = EVP_CIPHER_CTX_new();
		auto scope_handle = make_scope_handler(ctx);
		
		if(!EVP_EncryptInit_ex(ctx, cipher, nullptr, key, iv))
		{
			throw std::runtime_error("Error while trying to initialize symmetric cipher encrypt context!\n");
		}
		
		int out_len = static_cast<int>(data_len + iv_len);
		safe_vector<byte> output(out_len, 0);
		
		
		if(!EVP_EncryptUpdate(ctx, output.data(), &out_len, data, data_len))
		{
			throw std::runtime_error("EVP_EncryptUpdate failed!\n");
		}
		
		int out_len_final = static_cast<int>(output.size() - out_len);
		if(!EVP_EncryptFinal_ex(ctx, output.data() + out_len, &out_len_final))
		{
			throw std::runtime_error("EVP_EncryptFinal_ex failed!\n");
		}
		output.resize(out_len + out_len_final);
		return output;
		
	}

	safe_vector<byte> symmetric_encrypt(std::istream& stream,
										const byte * key, const std::size_t key_len,
										const byte * iv, const std::size_t iv_len,
										const EVP_CIPHER * cipher)
	{
		EVP_CIPHER_CTX * ctx = EVP_CIPHER_CTX_new();
		auto scope_handle = make_scope_handler(ctx);
		
		if(!EVP_EncryptInit_ex(ctx, cipher, nullptr, key, iv))
		{
			throw std::runtime_error("Error while trying to initialize encryption context for symmetric encription");
		}

		
		static constexpr int BUFFER_SIZE = 512;
		
		byte read_buffer[BUFFER_SIZE];
		byte write_buffer[BUFFER_SIZE + EVP_MAX_BLOCK_LENGTH];
		safe_vector<byte> result;
		char * read_buff_ch = reinterpret_cast<char *>(&read_buffer[0]);
		
		int out_length = 0;
		
		do
		{
			stream.read(read_buff_ch, BUFFER_SIZE);
			const auto count = stream.gcount();
			if(!EVP_EncryptUpdate(ctx, write_buffer, &out_length, read_buffer, count))
			{
				throw std::runtime_error("Error while trying to update encryption\n");
			}
			
			result.insert(result.end(), write_buffer, write_buffer + out_length);
		} while(stream);
	
		
		
		if(!EVP_EncryptFinal_ex(ctx, write_buffer, &out_length))
		{
			throw std::runtime_error("Error while trying to finalize encryption\n");
		}
		
		result.insert(result.end(), write_buffer, write_buffer + out_length);
		return result;
	}
	
	
	safe_vector<byte> symmetric_decrypt(const byte * data, const std::size_t data_len,
										const byte * key, const std::size_t key_len,
										const byte * iv, const std::size_t iv_len,
										const EVP_CIPHER * cipher)
	{
		EVP_CIPHER_CTX * ctx = EVP_CIPHER_CTX_new();
		auto scope_handle = make_scope_handler(ctx);
		
		if(!EVP_DecryptInit_ex(ctx, cipher, nullptr, key, iv))
		{
			throw std::runtime_error("Error while trying to initialize symmetric cipher decrypt context!\n");
		}
		
		safe_vector<byte> output(data_len, 0);
		int out_len = static_cast<int>(data_len);
		
		if(!EVP_DecryptUpdate(ctx, output.data(), &out_len, data, data_len))
		{
			throw std::runtime_error("EVP_DecryptUpdate failed!\n");
		}
		
		int out_len_final = static_cast<int>(output.size() - out_len);
		if(!EVP_DecryptFinal_ex(ctx, output.data() + out_len, &out_len_final))
		{
			throw std::runtime_error("EVP_DecryptFinal_ex failed!\n");
		}
		output.resize(out_len + out_len_final);
		return output;
		
	}

	safe_vector<byte> symmetric_decrypt(std::istream& stream,
										const byte * key, const std::size_t key_len,
										const byte * iv, const std::size_t iv_len,
										const EVP_CIPHER * cipher)
	{
		EVP_CIPHER_CTX * ctx = EVP_CIPHER_CTX_new();
		auto scope_handle = make_scope_handler(ctx);
		
		if(!EVP_DecryptInit_ex(ctx, cipher, nullptr, key, iv))
		{
			throw std::runtime_error("Error while trying to initialize encryption context for symmetric decryption");
		}

		
		static constexpr int BUFFER_SIZE = 512;
		
		byte read_buffer[BUFFER_SIZE];
		byte write_buffer[BUFFER_SIZE + EVP_MAX_BLOCK_LENGTH + 1];
		safe_vector<byte> result;
		char * read_buff_ch = reinterpret_cast<char *>(&read_buffer[0]);
		
		int out_length = 0;
		
		
		do
		{
			stream.read(read_buff_ch, BUFFER_SIZE);
			const auto count = stream.gcount();
			if(!EVP_DecryptUpdate(ctx, write_buffer, &out_length, read_buffer, count))
			{
				throw std::runtime_error("Error while trying to update decryption\n");
			}
			
			result.insert(result.end(), write_buffer, write_buffer + out_length);
		} while(stream);
		
		
		if(!EVP_DecryptFinal_ex(ctx, write_buffer, &out_length))
		{
			throw std::runtime_error("Error while trying to finalize decryption\n");
		}
		
		result.insert(result.end(), write_buffer, write_buffer + out_length);
		return result;
	}
};
