#include "vm_base.h"

#include "../backend/parser.hpp"
#include "../backend/encrypt.hpp"

#include "wx/sstream.h"
#include "wx/stdstream.h"
#include "wx/wfstream.h"

//#include <sstream>
#include <iomanip>						
#include <iostream>
#include <fstream>

vm_base::vm_base()
{
	rsa = RSA_new();
}

vm_base::~vm_base()
{
	if(rsa != nullptr)
	{
		RSA_free(rsa);
	}
}

void vm_base::rsa_data_change()
{
	this->not_up_to_date = true;
}

safe_vector<byte> vm_base::wx_hex_to_safe_vec(const wxString& hex)
{
	
	auto n = hex.size() / 2;
	safe_vector<byte> vec(n);
	const char * hex_str = hex.mb_str();
	for(size_t i = 0; i < n; ++i)
	{
		sscanf(hex_str + i * 2, "%02hhX", vec.data() + i);
	}
	
	return vec;
}

void vm_base::fill_stream_wtih_hex(std::ostream& stream, const byte * data, std::size_t len)
{	
	
	for(std::size_t i = 0; i < len; ++i)
	{
		stream << std::setw(2) << std::setfill('0') << std::hex << (int)data[i];
	}
}

wxString vm_base::rand_hex_of_size(std::size_t size_in_bits)
{
	std::size_t size = size_in_bits / 8;
	byte * data = new byte[size];
	crypt::random_byte_fill(data, size);
	
//	wxString result{};
	wxStringOutputStream wx_stream{};
	wxStdOutputStream std_stream(wx_stream);
	
	fill_stream_wtih_hex(std_stream, data, size);
	
	delete[] data;
	return wx_stream.GetString();
}

std::pair<wxString, wxString> vm_base::generate_n_and_d(std::size_t key_size, const wxString& hex_e)
{
	new_rsa();
	BIGNUM * e = BN_new();
	if(!BN_hex2bn(&e, hex_e.mb_str()))
	{
		std::cerr << "Error while trying to read public exponent (e) from given wxString, env_vm::generate_n_and_d\n";
		throw std::runtime_error("Error while trying to read public exponent (e) from given wxString, env_vm::generate_n_and_d\n");
//		return {wxString(), wxString()};
	}
	if(!RSA_generate_key_ex(rsa, key_size, e, nullptr))
	{
		std::cerr << "Error while trying to generate keys with key size: " << key_size << ", public exponent: " << hex_e << '\n';
		throw std::runtime_error("Error while trying to generate keys!");
	}
	const BIGNUM * n;
	const BIGNUM * d;
	RSA_get0_key(rsa, &n, nullptr, &d);
	if(!n || !d)
	{
		throw std::runtime_error("Error while trying to generate keys!");
	}
	
	this->not_up_to_date = false;
	return {wxString::FromAscii(BN_bn2hex(n)), wxString::FromAscii(BN_bn2hex(d))};
	
}

std::optional<std::tuple<wxString, wxString, wxString>> vm_base::rsa_data_from_nos(const wxString& contents)
{
	
	std::istringstream content_stream(contents.ToStdString());
	auto crypto_file_opt = parser::parse(content_stream);
	if(!crypto_file_opt.has_value())
		return std::nullopt;
	
	const crypto_file& file = crypto_file_opt.value();
	if(file.N.empty() || (file.d.empty() && file.e.empty()))
		return std::nullopt;
	
	wxStringOutputStream n_stream{};
	wxStdOutputStream std_n_stream(n_stream);
	fill_stream_wtih_hex(std_n_stream, file.N.data(), file.N.size());
	
	
	
	// izbjegni bespotrebno instanciranje pomocu lambda
	wxString e = [&file]()
	{ 
		if(!file.e.empty()) 
		{ 
			wxStringOutputStream e_stream{};
			wxStdOutputStream conversion_stream(e_stream);
			fill_stream_wtih_hex(conversion_stream, file.e.data(), file.e.size());
			return e_stream.GetString();
		}
		return wxString();
	}();
	
	wxString d = [&file]()
	{
		if(!file.d.empty())
		{
			wxStringOutputStream d_stream{};
			wxStdOutputStream conversion_stream(d_stream);
			fill_stream_wtih_hex(conversion_stream, file.d.data(), file.d.size());
			return d_stream.GetString();
		}
		return wxString();
	}();
	
	return {{n_stream.GetString(), e, d}};
}

std::size_t vm_base::rsa_key_size(int key_size_index) const noexcept
{
	std::size_t key_size = 512;
	for(int i = 0; i < key_size_index; ++i)
	{
		// 0 -> 512, 1 -> 1024, 2 -> 2048, 3 -> 4096
		key_size += key_size;
	}
	return key_size;
}


void vm_base::new_rsa()
{
	RSA_free(rsa);
	rsa = RSA_new();
	this->not_up_to_date = true;
}

bool vm_base::update_rsa(const wxString& n, const wxString& e, const wxString& d)
{
	if(!this->not_up_to_date) return true;
	
	BIGNUM * N = BN_new();
	BIGNUM * e_ = BN_new();
	BIGNUM * priv_exp = BN_new();

	
	if(!BN_hex2bn(&N, n.mb_str()) || !BN_hex2bn(&e_, e.mb_str()) || !BN_hex2bn(&priv_exp, d.mb_str()))
	{
		std::cerr << "Invliad RSA data!\n";
		return false;
	}
	RSA_set0_key(rsa, N, e_, priv_exp);
	this->not_up_to_date = false;
	return true;
}
