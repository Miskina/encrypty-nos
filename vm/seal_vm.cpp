#include "seal_vm.h"

#include "wx/sstream.h"
#include "wx/stdstream.h"
#include "wx/wfstream.h"

#include "../backend/parser.hpp"
#include "../backend/base64.h"
#include "../backend/encrypt.hpp"

std::optional<wxString> seal_vm::digital_seal(const wxString& in_file,
											  int symm_algo_idx,
											  int symm_key_size_idx,
											  int enc_type_idx,
											  const wxString& symm_key,
											  const wxString& init_v,
											  int rsa_key_size_index,
											  const wxString& n,
											  const wxString& e,
											  const wxString& d,
											  int digest_index)
{
	if(!this->check_params(n, e, d, in_file)) return std::nullopt;
	
	if(!this->update_rsa(n, e, d)) return std::nullopt;
	
	crypto_file file{};
	
	file.description = "Digital Seal";
	
	file.methods.push_back({env_vm::symm_algos[symm_algo_idx], this->symm_key_size(symm_algo_idx, symm_key_size_idx)});
	file.methods.push_back({"RSA", this->rsa_key_size(rsa_key_size_index)});
	
	
//	auto std_in_file = in_file.ToStdString();
	file.file_name = safe_string(in_file.begin(), in_file.end());
	
//	std::ifstream input(std_in_file);
	wxFileInputStream wx_file_input(in_file);
	wxStdInputStream input(wx_file_input);
	
	auto cipher = get_symm_alg(symm_algo_idx, symm_key_size_idx, enc_type_idx);
	
	auto symmetric_key = wx_hex_to_safe_vec(symm_key);
	auto iv = wx_hex_to_safe_vec(init_v);
	
	file.envelope_data = crypt::symmetric_encrypt(input, symmetric_key.data(), symmetric_key.size(), iv.data(), iv.size(), cipher);
	file.env_key = crypt::rsa_generic_operation(rsa, symmetric_key.data(), symmetric_key.size(), crypt::rsa_ops::encrypt);
	
	auto [digest_alg, digest_alg_name, digest_alg_size] = this->digest_alg_from_index(digest_index);
	crypt::hasher digester(digest_alg);
	
	digester.update(file.envelope_data.data(), file.envelope_data.size());
	digester.update(file.env_key.data(), file.env_key.size());
	auto digest_opt = digester.finalize();
	if(!digest_opt.has_value()) return std::nullopt;
	
	auto preprocess = this->rsa_op_preprocess_for(digest_alg);
	file.signature = crypt::rsa_generic_operation(rsa, digest_opt.value().data, digest_opt.value().length, crypt::rsa_ops::sign, preprocess);
	file.methods.push_back({safe_string(digest_alg_name), digest_alg_size});
	
	wxStringOutputStream sout{};
	wxStdOutputStream std_ss(sout);
	
	std_ss << file;
//	new_rsa();
	return {sout.GetString()};
}
std::optional<std::tuple<wxString,
						 wxString,
						 std::optional<wxString>>> seal_vm::unseal(const wxString& in_file,
																int symm_algo_idx,
																int symm_key_size_idx,
																int enc_type_idx,
																const wxString& symm_key,
																const wxString& init_vec,
																int rsa_key_size_index,
																const wxString& n,
																const wxString& e,
																const wxString& d,
																int digest_index)
{
	if(!check_params(n, e, d, in_file)) return std::nullopt;
	
	if(!this->update_rsa(n, e, d)) return std::nullopt;
	
	wxFileInputStream wx_file_input(in_file);
	wxStdInputStream file_input(wx_file_input);
	
	auto file_opt = parser::parse(file_input);
	if(!file_opt.has_value())
	{
		std::cerr << "Invalid input file\n";
		return std::nullopt;
	}
	
	auto file = file_opt.value();
	
	if(file.signature.empty() || file.methods.empty() || file.envelope_data.empty() || file.env_key.empty())
	{
		std::cerr << "Not enough data to unseal in given file\n";
		return std::nullopt;
	}
	
	auto [alg, alg_name, alg_size] = digest_alg_from_index(digest_index);
	
	for(const auto& [method, key_size] : file.methods)
	{
		auto method_sv = std::string_view(method);
		if(method_sv == alg_name)
		{
			if(key_size != alg_size)
			{
				std::cerr << "Cannot verify signature in given input file\nThe signature was hashed with a different algorithm\n";
				return std::nullopt;
			}
		} 
		else if("RSA" == method_sv)
		{
			if(key_size != this->rsa_key_size(rsa_key_size_index))
			{
				std::cerr << "Cannot verify signature in given input file\nThe signature was produced via a different RSA key size\n";
				return std::nullopt;
			}
		}
		else if(method == symm_algos[symm_algo_idx])
		{
			if(key_size != this->symm_key_size(symm_algo_idx, symm_key_size_idx))
			{
				std::cerr << "Cannot unseal envelope in given input file\nThe envelope data was sealed using a different symmetric key size\n";
				return std::nullopt;
			}
		}
	}
	
	crypt::hasher digester(alg);
	digester.update(file.envelope_data.data(), file.envelope_data.size());
	digester.update(file.env_key.data(), file.env_key.size());
	auto env_hash_opt = digester.finalize();
	if(!env_hash_opt.has_value()) return std::nullopt;
	
	auto preprocess = this->rsa_op_preprocess_for(alg);
	auto original_hash = crypt::rsa_generic_operation(rsa, file.signature.data(), file.signature.size(), crypt::rsa_ops::verify, preprocess);
	
	auto env_hash_b64 = b64_encode(env_hash_opt.value().data, env_hash_opt.value().length);
	auto org_hash_b64 = b64_encode(original_hash.data(), original_hash.size());
	
	wxString env_hash_wx = wxString(env_hash_b64.data(), env_hash_b64.length());
	wxString org_hash_wx = wxString(org_hash_b64.data(), org_hash_b64.length());
	
	if(env_hash_b64 != org_hash_b64)
	{
		return {{env_hash_wx, org_hash_wx, std::nullopt}};
	}
	
	return {{env_hash_wx, org_hash_wx, {this->open(file, symm_algo_idx, symm_key_size_idx, enc_type_idx, init_vec)}}};
}
