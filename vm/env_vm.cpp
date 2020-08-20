#include "env_vm.h"

#include "../backend/parser.hpp"
#include "../backend/encrypt.hpp"

#include "wx/sstream.h"
#include "wx/stdstream.h"
#include "wx/wfstream.h"

//#include <sstream>
#include <iomanip>						
#include <iostream>
#include <fstream>
											


const int env_vm::symm_key_sizes[] = {64, 128, 192, 256};
const safe_string env_vm::symm_algos[] = {"3-DES", "AES"};



std::optional<std::pair<wxString, wxString>> env_vm::symm_key_and_iv_from_nos(const wxString& contents)
{
	wxStringInputStream stream(contents);
	wxStdInputStream content_stream(stream);;
	auto crypto_file_opt = parser::parse(content_stream);
	if(!crypto_file_opt.has_value())
		return std::nullopt;
	
	crypto_file file = crypto_file_opt.value();
	if(file.iv.empty() && file.secret_key.empty())
		return std::nullopt;
	
	
	
	
	wxStringOutputStream key_stream{};
	wxStdOutputStream std_stream(key_stream);
	fill_stream_wtih_hex(std_stream, file.secret_key.data(), file.secret_key.size());
	
	wxStringOutputStream iv_stream{};
	wxStdOutputStream std_iv_stream(iv_stream);
	fill_stream_wtih_hex(std_iv_stream, file.iv.data(), file.iv.size());
	
	return {{key_stream.GetString(), iv_stream.GetString()}};
}

std::size_t env_vm::symm_key_size(int symm_algo_index, int key_size_index) const noexcept
{
	return 64 * (1 + symm_algo_index + symm_algo_index * key_size_index);
}

using cipher_factory = decltype(&EVP_aes_256_cbc);

static const EVP_CIPHER * cipher_aes_128(int enc_type_idx)
{
	static const cipher_factory factories[] = {&EVP_aes_128_cbc, &EVP_aes_128_cfb, &EVP_aes_128_ofb, &EVP_aes_128_ctr};
	return factories[enc_type_idx]();
}

static const EVP_CIPHER * cipher_aes_192(int enc_type_idx)
{
	static const cipher_factory factories[] = {&EVP_aes_192_cbc, &EVP_aes_192_cfb, &EVP_aes_192_ofb, &EVP_aes_192_ctr};
	return factories[enc_type_idx]();
}

static const EVP_CIPHER * cipher_aes_256(int enc_type_idx)
{
	static const cipher_factory factories[] = {&EVP_aes_256_cbc, &EVP_aes_256_cfb, &EVP_aes_256_ofb, &EVP_aes_256_ctr};
	return factories[enc_type_idx]();
}

static const EVP_CIPHER * cipher_3_des(int enc_type_idx)
{
	static const cipher_factory factories[] = {&EVP_des_ede3_cbc, &EVP_des_ede3_cfb, &EVP_des_ede3_ofb};
	return factories[enc_type_idx]();
}

using cipher_picker = decltype(&cipher_aes_128);

static cipher_picker pick_key_size_aes(int key_size_idx)
{
	static cipher_picker cipher_pickers[] = {&cipher_aes_128, &cipher_aes_192, &cipher_aes_256};
	return cipher_pickers[key_size_idx];
}

static cipher_picker pick_key_size_des(int key_size_idx)
{
	return &cipher_3_des;
}

using key_size_picker = decltype(&pick_key_size_aes);

static key_size_picker pick_symm_algo(int symm_algo_idx)
{
	static key_size_picker size_pickers[] = {&pick_key_size_des, &pick_key_size_aes};
	return size_pickers[symm_algo_idx];
}





std::optional<wxString> env_vm::seal(const wxString& in_file,
										   int symm_algo_idx,
										   int symm_key_size_idx,
										   int enc_type_idx,
										   const wxString& symm_key,
										   const wxString& init_v,
										   int rsa_key_size_index,
										   const wxString& n,
										   const wxString& e,
										   const wxString& d)
{
	if(in_file.empty() || e.empty() || n.empty() || symm_key.empty() || init_v.empty()) return std::nullopt;
	
	if(this->not_up_to_date && !this->update_rsa(n, e, d)) return std::nullopt;
	
	crypto_file file{};
	
	file.description = "Envelope";
	
	file.methods.push_back({symm_algos[symm_algo_idx], this->symm_key_size(symm_algo_idx, symm_key_size_idx)});
	file.methods.push_back({"RSA", this->rsa_key_size(rsa_key_size_index)});
	
	
//	auto std_in_file = in_file.ToStdString();
	file.file_name = safe_string(in_file.begin(), in_file.end());
	
//	std::ifstream input(std_in_file);
	wxFileInputStream wx_file_input(in_file);
	wxStdInputStream input(wx_file_input);
	
	auto cipher = pick_symm_algo(symm_algo_idx)(symm_key_size_idx)(enc_type_idx);
	
	auto symmetric_key = wx_hex_to_safe_vec(symm_key);
	auto iv = wx_hex_to_safe_vec(init_v);
	
	file.envelope_data = crypt::symmetric_encrypt(input, symmetric_key.data(), symmetric_key.size(), iv.data(), iv.size(), cipher);
	file.env_key = crypt::rsa_generic_operation(rsa, symmetric_key.data(), symmetric_key.size(), crypt::rsa_ops::encrypt);
	
	wxStringOutputStream sout{};
	wxStdOutputStream std_ss(sout);
	
	std_ss << file;
//	new_rsa();
	return {sout.GetString()};
}

std::optional<wxString> env_vm::open(const wxString& in_file,
										   int symm_algo_idx,
										   int symm_key_size_idx,
										   int enc_type_idx,
										   const wxString& init_v,
										   int rsa_key_size_index,
										   const wxString& n,
										   const wxString& e,
										   const wxString& d)
{
    if(in_file.empty() || e.empty() || n.empty() || init_v.empty()) return std::nullopt;
	
	if(this->not_up_to_date && !this->update_rsa(n, e, d)) return std::nullopt;
	
	wxFileInputStream wx_file_input(in_file);
	wxStdInputStream file_input(wx_file_input);
	auto file_opt = parser::parse(file_input);
	if(!file_opt.has_value())
	{
		std::cerr << "Invalid input file\n";
		return std::nullopt;
	}
	
	auto file = file_opt.value();
	
	if(file.env_key.empty() || file.envelope_data.empty())
	{
		return std::nullopt;
	}
	
	// Podaci dani u GUI-u bi trebali odgovarati onima u datoteci
	for(const auto& [method, key_size] : file.methods)
	{
		if(method == symm_algos[symm_algo_idx])
		{
			if(key_size != this->symm_key_size(symm_algo_idx, symm_key_size_idx))
			{
				std::cerr << "Cannot open envelope in given input file\nThe envelope data was sealed using a different symmetric key size\n";
				return std::nullopt;
			}
		} 
		else if("RSA" == method)
		{
			if(key_size != this->rsa_key_size(rsa_key_size_index))
			{
				std::cerr << "Cannot open envelope in given input file\nThe envelope data was sealed using a different RSA key size\n";
				return std::nullopt;
			}
		}
		else
		{
			std::cerr << "Cannot open envelope in given input file\nThe envelope data was sealed using a different algorithm than what was specified\n";
			return std::nullopt;
		}
	}
	return open(file, symm_algo_idx, symm_key_size_idx, enc_type_idx, init_v);
//	auto iv = wx_hex_to_safe_vec(init_v);
//	auto cipher = pick_symm_algo(symm_algo_idx)(symm_key_size_idx)(enc_type_idx);
//	auto symmetric_key = crypt::rsa_generic_operation(rsa, file.env_key.data(), file.env_key.size(), crypt::rsa_ops::decrypt);
//	
//	auto decrypted_data_vec = crypt::symmetric_decrypt(file.envelope_data.data(), file.envelope_data.size(), symmetric_key.data(), symmetric_key.size(), iv.data(), iv.size(), cipher);		
////	new_rsa();
//	return {wxString::FromAscii(decrypted_data_vec.data(), decrypted_data_vec.size())};
}
std::optional<wxString> env_vm::open(const crypto_file& file,
									 int symm_algo_idx,
									 int symm_key_size_idx,
									 int enc_type_idx,
									 const wxString& init_v)
{
	
	auto iv = wx_hex_to_safe_vec(init_v);
	auto cipher = pick_symm_algo(symm_algo_idx)(symm_key_size_idx)(enc_type_idx);
	auto symmetric_key = crypt::rsa_generic_operation(rsa, file.env_key.data(), file.env_key.size(), crypt::rsa_ops::decrypt);
	
	auto decrypted_data_vec = crypt::symmetric_decrypt(file.envelope_data.data(), file.envelope_data.size(), symmetric_key.data(), symmetric_key.size(), iv.data(), iv.size(), cipher);		
//	new_rsa();
	return {wxString::FromUTF8(decrypted_data_vec.data(), decrypted_data_vec.size())};
}

const EVP_CIPHER * env_vm::get_symm_alg(int symm_algo_idx, int symm_key_size_idx, int enc_type_idx)
{
	return pick_symm_algo(symm_algo_idx)(symm_key_size_idx)(enc_type_idx);
}