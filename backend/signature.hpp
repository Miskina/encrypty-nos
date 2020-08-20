#ifndef SIGNATURE_HPP
#define SIGNATURE_HPP

#include "openssl_types_util.hpp"
#include "crypto_file.hpp"

#include <optional>
#include <istream>

namespace crypt
{
	
	/*
	 * Pomocna struktura koja sadrzi podatke o sazetku poruke.
	 * 
	 * data - sazetak u byte-ovima
	 * length - velicina sazetka
	 * type - tip sazetka dan kao OpenSSL-ov NID (npr. NID od SHA2-256)
	 * */
	struct hashed_data
	{
		byte data[EVP_MAX_MD_SIZE];
		unsigned int length = 0;
		int type;
	};
	
	/*
	 * Funkcija za izracunavanje sazetka poruke.
	 * 
	 * Prima poruku ciji sazetak treba izracunat i implementaciju algoritma koji to izvrsava.
	 * 
	 * */
	std::optional<hashed_data> hash(const safe_string& msg, const EVP_MD * algorithm = EVP_sha3_256());
	
	/*
	 * Funkcija za izracunavanje sazetka poruke.
	 * 
	 * Prima stream preko kojeg dobiva poruku i implementaciju algoritma koji izvrsava izracun sazteka
	 * */
	std::optional<hashed_data> hash(std::istream& stream, const EVP_MD * algorithm = EVP_sha3_256());
	
	struct hasher
	{
		hasher(const EVP_MD * alg);
		~hasher();
		
		void update(const byte * data, std::size_t len);
		void update(const char * data, std::size_t len);
		void update(std::istream& stream);
		
		std::optional<hashed_data> finalize() noexcept;
		
	private:
		EVP_MD_CTX * ctx;
		int alg_type;
	};

	/*
	 * Funkcija za izracun potpisa pomocu RSA algoritma.
	 * 
	 * Prima sazetak poruke, te velicinu sazetka i velicinu RSA kljuca.
	 * Pomocu velicine i standradnog RSA_F4 = 65537 eksponenta
	 * */
//	safe_vector<byte> sign_digest(const byte * msg_digest,
//								  const std::size_t digest_len,
//								  const std::size_t key_length,
//								  const EVP_MD * alg);
	
	/*
	 * Funkcija za izracun potpisa pomocu RSA algoritma.
	 * 
	 * Prima sazetak poruke, velicinu sazetka, privatni eksponent(d) u byteovima, velicinu eksponenta,
	 * broj modul(N) u byteovima i velicinu modula.
	 * 
	 * Ako nije zadan privatni eksponent(priv_exp = nullptr) tada se generiraju novi kljucevi pomocu danog
	 * modulusa i velicine modulusa
	 * */
//	safe_vector<byte> sign_digest(const byte * msg_digest, const std::size_t digest_len,
//								  const byte * modulus, const std::size_t modulus_len,
//								  const byte * priv_exp, const std::size_t priv_exp_len,
//								  const EVP_MD * alg);

	
};

#endif // SIGNATURE_HPP
