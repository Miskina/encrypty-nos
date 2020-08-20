#ifndef VM_BASE_H
#define VM_BASE_H

#include "wx/string.h"

#include <optional>
#include <utility>
#include <ostream>

#include "../backend/openssl_types_util.hpp"

#include <openssl/rsa.h>

struct vm_base
{

	vm_base();
	virtual ~vm_base();
	
	wxString rand_hex_of_size(std::size_t size_in_bits);
	
	std::pair<wxString, wxString> generate_n_and_d(std::size_t key_size, const wxString& hex_e);
	
	void rsa_data_change();
	
	std::optional<std::tuple<wxString, wxString, wxString>> rsa_data_from_nos(const wxString& nos_contents);
	
	std::size_t rsa_key_size(int key_size_index) const noexcept;

protected:
	
	RSA * rsa;
	bool not_up_to_date = false;
	
	static safe_vector<byte> wx_hex_to_safe_vec(const wxString& hex);
	static void fill_stream_wtih_hex(std::ostream& stream, const byte * data, std::size_t len);
	
	void new_rsa();
	
	bool update_rsa(const wxString& n, const wxString& e, const wxString& d); 
};

#endif // VM_BASE_H
