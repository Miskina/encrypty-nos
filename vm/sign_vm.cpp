#include "sign_vm.h"

#include "wx/sstream.h"
#include "wx/stdstream.h"
#include "wx/wfstream.h"

#include "../backend/parser.hpp"
#include "../backend/base64.h"
#include "../backend/encrypt.hpp"



std::optional<wxString> sign_vm::sign(int digest_alg_index,
									  int rsa_key_size_index,
									  const wxString& n,
									  const wxString& e,
									  const wxString& d,
									  const wxString& in_file)
{
	
	if(!check_params(n, e, d, in_file)) return std::nullopt;
	
	if(this->not_up_to_date && !this->update_rsa(n, e, d)) return std::nullopt;
	
	wxFileInputStream wx_file_input(in_file);
	wxStdInputStream file_input(wx_file_input);
	
	auto [alg, alg_name, alg_size] = this->digest_alg_from_index(digest_alg_index);
	auto hash_opt = crypt::hash(file_input, alg);
	if(!hash_opt.has_value())
	{
		std::cerr << "Hashing failed!\n";
		return std::nullopt;
	}
	
	crypto_file file{};
	
	file.description = "Signature";
	file.methods.push_back({safe_string(alg_name), alg_size});
	file.methods.push_back({"RSA", this->rsa_key_size(rsa_key_size_index)});
	
	file.file_name = safe_string(in_file.begin(), in_file.end());
	
	auto hash = hash_opt.value();
	
	auto preprocess = rsa_op_preprocess_for(alg);
	file.signature = crypt::rsa_generic_operation(rsa, hash.data, hash.length, crypt::rsa_ops::sign, preprocess);
	
	wxStringOutputStream wx_sstream{};
	wxStdOutputStream std_out(wx_sstream);
	
	std_out << file;
	
	return {wx_sstream.GetString()};
}

std::optional<std::tuple<wxString, wxString, bool>> sign_vm::verify_recover(int digest_alg_index,
												int rsa_key_size_index,
												const wxString& n,
												const wxString& e,
												const wxString& d,
												const wxString& in_file,
												const wxString& msg_file)
{
	if(!check_params(n, e, d, in_file) || msg_file.empty()) return std::nullopt;
	
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
	
	if(file.signature.empty() || file.methods.empty())
	{
		std::cerr << "No signature to verify in given file\n";
		return std::nullopt;
	}
	
	auto [alg, alg_name, alg_size] = digest_alg_from_index(digest_alg_index);
	
	for(const auto& [method, size] : file.methods)
	{
		auto method_sv = std::string_view(method);
		if(method_sv == alg_name)
		{
			if(size != alg_size)
			{
				std::cerr << "Cannot verify signature in given input file\nThe signature was hashed with a different algorithm\n";
				return std::nullopt;
			}
		} 
		else if("RSA" == method_sv)
		{
			if(size != this->rsa_key_size(rsa_key_size_index))
			{
				std::cerr << "Cannot verify signature in given input file\nThe signature was produced via a different RSA key size\n";
				return std::nullopt;
			}
		}
		else if(method_sv.substr(0, 3) == "SHA")
		{
			std::cerr << "Cannot verify signature in given input file\nThe signature was hashed with a different algorithm\n";
			return std::nullopt;
		}
	}
	
	wxFileInputStream msg_file_stream(msg_file);
	wxStdInputStream msg_stream(msg_file_stream);
	
	auto hash_opt = crypt::hash(msg_stream, alg);
	if(!hash_opt.has_value())
	{
		std::cerr << "Failed to hash the original message!\n";
		return std::nullopt;
	}
	
	auto hash_val = hash_opt.value();
	auto preprocess = rsa_op_preprocess_for(alg);
	auto original_hash = crypt::rsa_generic_operation(rsa, file.signature.data(), file.signature.size(), crypt::rsa_ops::verify, preprocess);
	
	auto msg_hash_b64 = b64_encode(hash_val.data, hash_val.length);
	auto org_hash_b64 = b64_encode(original_hash);

	return {{wxString(msg_hash_b64.data(), msg_hash_b64.length()),
			wxString(org_hash_b64.data(), org_hash_b64.length()),
			msg_hash_b64 == org_hash_b64}};
}

bool sign_vm::check_params(const wxString& n,
						   const wxString& e,
						   const wxString& d,
						   const wxString& in_file)
{
	return !(n.empty() || e.empty() || d.empty() || in_file.empty());
}


std::tuple<const EVP_MD *, std::string_view, int> sign_vm::digest_alg_from_index(int index)
{
	using digest_alg_factory = decltype(&EVP_sha3_512);
	static constexpr digest_alg_factory factories[] = {&EVP_sha3_256, &EVP_sha3_512, &EVP_sha256, &EVP_sha512};
	static const std::string_view alg_names[] = {"SHA3", "SHA3", "SHA2", "SHA2"};
	
	if(index < 0 || index >= 4) throw std::runtime_error("Invalid sha algorithm index");
	
	
	
	return {factories[index](), alg_names[index], 256 * ((index % 2) + 1)};
}

