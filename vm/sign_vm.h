#ifndef SIGN_VM_H
#define SIGN_VM_H

#include "vm_base.h"

#include "../backend/signature.hpp"

#include <string_view>
#include <tuple>

struct sign_vm : public virtual vm_base
{
	std::optional<wxString> sign(int digest_alg_index,
								 int rsa_key_size_index,
								 const wxString& n_str,
								 const wxString& e_str,
								 const wxString& d_str,
								 const wxString& in_file);
	
	std::optional<std::tuple<wxString, wxString, bool>> verify_recover(int digest_alg_index,
										   int rsa_key_size_index,
										   const wxString& n_str,
										   const wxString& e_str,
										   const wxString& d_str,
										   const wxString& in_file,
										   const wxString& msg_file);

	
protected:
	bool check_params(const wxString& n_str, const wxString& e_str, const wxString& d_str, const wxString& in_file);
	
	std::tuple<const EVP_MD *, std::string_view, int> digest_alg_from_index(int index);
		
	static auto rsa_op_preprocess_for(const EVP_MD * alg)
	{
		return [alg](EVP_PKEY_CTX * ctx)
					{
						return EVP_PKEY_CTX_set_signature_md(ctx, alg);
					};
	}
};

#endif // SIGN_VM_H
