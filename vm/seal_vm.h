#ifndef SEAL_VM_H
#define SEAL_VM_H

#include "env_vm.h"
#include "sign_vm.h"

#include <utility>
#include <tuple>

struct seal_vm : public env_vm, public sign_vm
{
	std::optional<wxString> digital_seal(const wxString& in,
										 int algo_idx,
										 int s_key_size_idx,
										 int enc_type_idx,
										 const wxString& s_key,
										 const wxString& init_vec,
										 int rsa_key_size_index,
										 const wxString& N,
										 const wxString& pub_exp,
										 const wxString& priv_exp,
										 int digest_index);
										 
	std::optional<std::tuple<wxString,
							 wxString,
							 std::optional<wxString>>> unseal(const wxString& in,
														 int algo_idx,
														 int s_key_size_idx,
														 int enc_type_idx,
														 const wxString& s_key,
														 const wxString& init_vec,
														 int rsa_key_size_index,
														 const wxString& N,
														 const wxString& pub_exp,
														 const wxString& priv_exp,
														 int digest_index);
};

#endif // SEAL_VM_H
