#ifndef ENV_MODEL_H
#define ENV_MODEL_H

#include "vm_base.h"

#include "../backend/crypto_file.hpp"

struct env_vm : public virtual vm_base
{
	
	std::optional<std::pair<wxString, wxString>> symm_key_and_iv_from_nos(const wxString& contents);
	
	std::optional<wxString> seal(const wxString& in,
								    int algo_idx,
								    int s_key_size_idx,
								    int enc_type_idx,
								    const wxString& s_key,
								    const wxString& init_vec,
								    int rsa_key_size_index,
								    const wxString& N,
								    const wxString& pub_exp,
								    const wxString& priv_exp);
//	std::optional<crypto_file> parse_stream_contents(std::istream& stream);
	std::size_t symm_key_size(int symm_algo_index, int key_size_index) const noexcept;
	
	
	std::optional<wxString> open(const wxString& in,
								    int algo_idx,
								    int s_key_size_idx,
								    int enc_type_idx,
								    const wxString& init_vec,
								    int rsa_key_size_index,
								    const wxString& N,
								    const wxString& pub_exp,
								    const wxString& priv_exp);
	
protected:
	
	static const int symm_key_sizes[];
	static const safe_string symm_algos[];
	
	std::optional<wxString> open(const crypto_file& file,
								 int symm_algo_idx,
								 int symm_key_size_idx,
								 int enc_type_idx,
								 const wxString& init_vp);
	
	static const EVP_CIPHER * get_symm_alg(int symm_algo_idx, int symm_key_size_idx, int enc_type_idx);
	
};

#endif // ENV_PANEL_VM_H
