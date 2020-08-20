#include "signature.hpp"
#include "encrypt.hpp"

#include <iostream>

#include <openssl/rsa.h>

namespace crypt
{
	
	static constexpr std::size_t BUFFER_SIZE = 512;
	
	std::optional<hashed_data> hash(const safe_string& msg, const EVP_MD * algorithm)
	{
		EVP_MD_CTX * ctx = EVP_MD_CTX_new();
		auto scope_handle = make_scope_handler(ctx);
		
		if(ctx == nullptr)
		{
			return std::nullopt;
		}
		
		if(!EVP_DigestInit_ex(ctx, algorithm, nullptr)) 
		{
			return std::nullopt;
		}
		
		if(!EVP_DigestUpdate(ctx, msg.c_str(), msg.length())) 
		{
			return std::nullopt;
		}
		
		hashed_data hash{};
		hash.type = EVP_MD_type(algorithm);
//		hash.msg = std::move(msg);
		
		if(!EVP_DigestFinal_ex(ctx, hash.data, &hash.length)) 
		{
			return std::nullopt;
		}
		
//		EVP_MD_CTX_free(ctx);
		
		return {hash};
	}
	
	std::optional<hashed_data> hash(std::istream& stream, const EVP_MD * algorithm)
	{
		if(!stream)
		{
			return std::nullopt;
		}

		
		auto ctx = EVP_MD_CTX_new();
		if(ctx == nullptr)
		{
			return std::nullopt;
		}
		
		auto scope_handle = make_scope_handler(ctx);
		
		if(!EVP_DigestInit_ex(ctx, algorithm, nullptr))
		{
			return std::nullopt;
		}		
//		static constexpr std::size_t BUFFER_SIZE = 512;
		char buffer[BUFFER_SIZE];
		std::size_t read = 0;
		
		hashed_data hash{};
		hash.type = EVP_MD_type(algorithm);
		
		do
		{
			stream.read(buffer, BUFFER_SIZE);
			std::size_t count = stream.gcount();
			if(!EVP_DigestUpdate(ctx, buffer, count))
			{
				std::cerr << "Failed EVP_DigestUpdate\n";
				return std::nullopt;
			}
			read += count;
		} while(stream);
		
//		while(stream.read(buffer, BUFFER_SIZE))
//		{
//			std::size_t count = stream.gcount();
//			if(!EVP_DigestUpdate(ctx, buffer, count))
//			{
//				std::cerr << "Failed EVP_DigestUpdate\n";
//				return std::nullopt;
//			}
//			read += count;
//		}
		
		
		
		if(!EVP_DigestFinal_ex(ctx, hash.data, &hash.length))
		{
			std::cerr << "Failed EVP_DigestFinal\n";
			return std::nullopt;
		}
		
		return {hash};
		
	}
	
	hasher::hasher(const EVP_MD * alg)
	{
		ctx = EVP_MD_CTX_new();
		if(ctx == nullptr || !EVP_DigestInit_ex(ctx, alg, nullptr))
			throw std::runtime_error("Failed to initialize context for hasher");
		alg_type = EVP_MD_type(alg);
	}
	
	hasher::~hasher()
	{
		EVP_MD_CTX_free(ctx);
	}
	
	void hasher::update(const byte * data, std::size_t len)
	{
		if(!EVP_DigestUpdate(ctx, data, len))
		{
			throw std::runtime_error("Error while trying to update digest context");
		}
	}
	
	void hasher::update(const char * data, std::size_t len)
	{
		if(!EVP_DigestUpdate(ctx, data, len))
		{
			throw std::runtime_error("Error while trying to update digest context");
		}
	}
	
	void hasher::update(std::istream& stream)
	{
		if(!stream)
		{
			throw std::runtime_error("Given invalid stream to update hash data with");
		}
		
		
		char buffer[BUFFER_SIZE];
		std::size_t read = 0;
		
		do
		{
			stream.read(buffer, BUFFER_SIZE);
			std::size_t count = stream.gcount();
			if(!EVP_DigestUpdate(ctx, buffer, count))
			{
				std::cerr << "Failed EVP_DigestUpdate\n";
				throw std::runtime_error("Failed to update digest with data from given stream");
			}
			read += count;
		} while(stream);
	}
	
	std::optional<hashed_data> hasher::finalize() noexcept
	{
		hashed_data hash{};
		if(!EVP_DigestFinal_ex(ctx, hash.data, &hash.length))
		{
			std::cerr << "Failed EVP_DigestFinal\n";
			return std::nullopt;
		}
		
		return {hash};
	}
	
	
	
//	safe_vector<byte> sign_digest(const byte * msg_digest, const std::size_t digest_len,
//								  const byte * modulus, const std::size_t modulus_len,
//								  const byte * priv_exp, const std::size_t priv_exp_len, const EVP_MD * alg)
//	{
//		
//		RSA * rsa = RSA_new();
//		auto scope_handler = make_scope_handler(rsa);
//		
//		BIGNUM * n = BN_bin2bn(modulus, modulus_len, nullptr);
//		if(priv_exp != nullptr)
//		{
//			RSA_set0_key(rsa, n, nullptr, BN_bin2bn(priv_exp, priv_exp_len, nullptr));
//		}
//		else
//		{
//			RSA_generate_key_ex(rsa, modulus_len, n, nullptr);
//		}
//		
//		return rsa_generic_operation(rsa, msg_digest, digest_len, rsa_ops::sign, rsa_op_preprocess_for(alg));
////		return rsa_generic_operation(rsa, msg_digest, digest_len, &RSA_private_encrypt);
//	}
//	
//	safe_vector<byte> sign_digest(const byte * msg_digest,
//								  const std::size_t digest_len,
//								  const std::size_t key_length,
//								  const EVP_MD * alg)
//	{
//		
//		RSA * rsa = RSA_new();
//		auto scope_handle = make_scope_handler(rsa);
//		BIGNUM * e = BN_new();
//		BN_set_word(e, RSA_F4);
//		
//		RSA_generate_key_ex(rsa, key_length, e, nullptr);
//		
//		return rsa_generic_operation(rsa, msg_digest, digest_len, rsa_ops::sign, rsa_op_preprocess_for(alg));
//		
//	}
	
};

