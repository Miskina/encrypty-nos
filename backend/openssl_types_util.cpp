#include "openssl_types_util.hpp"

namespace crypt
{
	void destroy_impl(EVP_MD_CTX * ctx)
	{
		EVP_MD_CTX_free(ctx);
	}
	
	void destroy_impl(EVP_CIPHER_CTX * ctx)
	{
		EVP_CIPHER_CTX_free(ctx);
	}
	
	void destroy_impl(EVP_PKEY_CTX * ctx)
	{
		EVP_PKEY_CTX_free(ctx);
	}
	
	void destroy_impl(EVP_PKEY * key)
	{
		EVP_PKEY_free(key);
	}
	
	void destroy_impl(RSA * rsa)
	{
		RSA_free(rsa);
	}
};