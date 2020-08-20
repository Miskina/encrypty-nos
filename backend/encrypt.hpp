#ifndef ENCRYPT_HPP
#define ENCRYPT_HPP

#include "openssl_types_util.hpp"

#include <openssl/rsa.h>
#include <openssl/evp.h>
#include <openssl/err.h>

#include <istream>
#include <utility>

namespace crypt
{
	using rsa_operation = decltype(&EVP_PKEY_encrypt);
	using rsa_op_init = decltype(&EVP_PKEY_encrypt_init);
	
	namespace rsa_ops
	{
		using op_init_pair = std::pair<rsa_operation, rsa_op_init>;
		static constexpr op_init_pair encrypt = {&EVP_PKEY_encrypt, &EVP_PKEY_encrypt_init};
		static constexpr op_init_pair decrypt = {&EVP_PKEY_decrypt, &EVP_PKEY_decrypt_init};
		static constexpr op_init_pair sign = {&EVP_PKEY_sign, &EVP_PKEY_sign_init};
		static constexpr op_init_pair verify = {&EVP_PKEY_verify_recover, &EVP_PKEY_verify_recover_init};
	};
	
//	template<typename ... Args>
//	safe_vector<byte> rsa_generic_operation(RSA * rsa, const byte * source_data, const std::size_t source_len, const rsa_operation op, const rsa_op_init init, const int padding = RSA_PKCS1_PADDING);

	
	template<typename ... PreprocessOps>
	safe_vector<byte> rsa_generic_operation(RSA * rsa, const byte * source_data, const std::size_t source_len, const int padding, const rsa_operation& op, const rsa_op_init& init, PreprocessOps&& ... preprocess_ops)
	{
		EVP_PKEY * key = EVP_PKEY_new();
		if(!EVP_PKEY_set1_RSA(key, rsa))
		{
			destroy_impl(key);
			throw std::runtime_error("Unable to use the specified RSA parameters!");
		}
		
		EVP_PKEY_CTX * ctx = EVP_PKEY_CTX_new(key, nullptr);
		auto scope_handle = make_scope_handler(key, ctx);
		
		if(!key || !ctx)
		{
			throw std::runtime_error("Unable to setup and allocate context for the RSA operation!");
		}
		
		if(init(ctx) <= 0)
		{
			throw std::runtime_error("Unable to initialize RSA operation context, the given init function failed!");
		}
		
		if(EVP_PKEY_CTX_set_rsa_padding(ctx, padding) <= 0)
		{
			throw std::runtime_error("Unable to set the given or default RSA padding to operation context!");
		}
		
		if constexpr(sizeof...(preprocess_ops) > 0)
		{			
			if((preprocess_ops(ctx), ...) <= 0)
			{
				throw std::runtime_error("Failed a specified preprocessing operation!");
			}
		}
		
		// odredi duljinu izlaza
		std::size_t out_len = 0;
		if(op(ctx, nullptr, &out_len, source_data, source_len) <= 0)
		{
			throw std::runtime_error("Given RSA operation failed while trying to determine the size of the output");
		}
		safe_vector<byte> out(out_len, 0);
		
		int op_ret = op(ctx, out.data(), &out_len, source_data, source_len);
		if(op_ret <= 0)
		{
			ERR_print_errors_fp(stderr);
			throw std::runtime_error("Failed to execute the given RSA operation");
		}
		out.resize(out_len);
		return out;

	}
	
	template<typename ... PreprocessOps>
	safe_vector<byte> rsa_generic_operation(RSA * rsa, const byte * source_data, const std::size_t source_len, const rsa_ops::op_init_pair& op_pair, PreprocessOps&& ... preprocess_ops)
	{
		auto [op, init] = op_pair;
		return rsa_generic_operation(rsa, source_data, source_len, RSA_PKCS1_PADDING, op, init, std::forward<PreprocessOps>(preprocess_ops)...);
	}


	
	void random_byte_fill(byte * data, const std::size_t len);
	
	safe_vector<byte> symmetric_encrypt(const byte * data, const std::size_t data_len,
										const byte * key, const std::size_t key_len,
										const byte * iv, const std::size_t iv_len,
										const EVP_CIPHER * cipher = EVP_aes_256_cbc());
										
	safe_vector<byte> symmetric_encrypt(std::istream& stream,
										const byte * key, const std::size_t key_len,
										const byte * iv, const std::size_t iv_len,
										const EVP_CIPHER * cipher = EVP_aes_256_cbc());
										
	
	safe_vector<byte> symmetric_decrypt(const byte * data, const std::size_t data_len,
										const byte * key, const std::size_t key_len,
										const byte * iv, const std::size_t iv_len,
										const EVP_CIPHER * cipher);

	safe_vector<byte> symmetric_decrypt(std::istream& stream,
										const byte * key, const std::size_t key_len,
										const byte * iv, const std::size_t iv_len,
										const EVP_CIPHER * cipher);
	
};
#endif // ENCRYPT_HPP
