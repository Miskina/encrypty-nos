#include "signature_window.h"

#include "compare_dialog.h"
#include "file_preview_dialog.h"
#include "scope_exit.h"

#include <openssl/err.h>

#define SIGN_DEBUG 1

signature_window::signature_window(wxWindow * parent, wxWindowID id) : wxScrolledWindow(parent, id, wxDefaultPosition, wxDLG_UNIT(parent, wxSize(-1,-1)), wxHSCROLL|wxVSCROLL)
{
	this->SetScrollRate(5, 5);
	
	wxBoxSizer* sign_window_sizer = new wxBoxSizer(wxVERTICAL);
    this->SetSizer(sign_window_sizer);
    
    wxBoxSizer* digest_alg_sizer = new wxBoxSizer(wxHORIZONTAL);
    
    sign_window_sizer->Add(digest_alg_sizer, 0, wxALL|wxEXPAND, 5);
    
    digest_alg_sizer->Add(0, 0, 1, wxALL|wxEXPAND, 5);
    
    wxArrayString digest_alg_rbArr;
    digest_alg_rbArr.Add(_("SHA3-256"));
    digest_alg_rbArr.Add(_("SHA3-512"));
    digest_alg_rbArr.Add(_("SHA2-256"));
    digest_alg_rbArr.Add(_("SHA2-512"));
    digest_alg_rb = new wxRadioBox(this, wxID_ANY, _("Digest algorithm"), wxDefaultPosition, wxDLG_UNIT(this, wxSize(-1,-1)), digest_alg_rbArr, 2, 0);
    digest_alg_rb->SetSelection(0);
    
    digest_alg_sizer->Add(digest_alg_rb, 1, wxALL|wxEXPAND, 5);
    
    digest_alg_sizer->Add(0, 0, 1, wxALL|wxEXPAND, 5);
    
    line1 = new wxStaticLine(this, wxID_ANY, wxDefaultPosition, wxDLG_UNIT(this, wxSize(-1,-1)), wxLI_HORIZONTAL);
    
    sign_window_sizer->Add(line1, 0, wxALL|wxEXPAND, 5);
    
    asymm_lbl = new wxStaticText(this, wxID_ANY, _("Asymmetric data"), wxDefaultPosition, wxDLG_UNIT(this, wxSize(-1,-1)), wxALIGN_CENTRE);
    
    sign_window_sizer->Add(asymm_lbl, 0, wxALL|wxEXPAND, 5);
    
    wxBoxSizer* asymm_sizer = new wxBoxSizer(wxHORIZONTAL);
    
    sign_window_sizer->Add(asymm_sizer, 0, wxALL|wxEXPAND, 5);
    
    wxArrayString rsa_key_rbArr;
    rsa_key_rbArr.Add(_("512"));
    rsa_key_rbArr.Add(_("1024"));
    rsa_key_rbArr.Add(_("2048"));
    rsa_key_rbArr.Add(_("4096"));
    rsa_key_rb = new wxRadioBox(this, wxID_ANY, _("Asymetric(RSA) Key Size"), wxDefaultPosition, wxDLG_UNIT(this, wxSize(-1,-1)), rsa_key_rbArr, 2, 0);
    rsa_key_rb->SetSelection(0);
    
    asymm_sizer->Add(rsa_key_rb, 1, wxALL, 5);
    
    gen_key_e_btn = new wxButton(this, wxID_ANY, _("Generate from key size and public exponent"), wxDefaultPosition, wxDLG_UNIT(this, wxSize(-1,-1)), 0);
    
    asymm_sizer->Add(gen_key_e_btn, 2, wxALL|wxEXPAND, 5);
    
    asym_nos_btn = new wxButton(this, wxID_ANY, _("Asymmetric data from NOS file"), wxDefaultPosition, wxDLG_UNIT(this, wxSize(-1,-1)), 0);
    
    asymm_sizer->Add(asym_nos_btn, 1, wxALL|wxEXPAND, 5);
    
    asymm_rsa_key_lbl = new wxStaticText(this, wxID_ANY, _("Asymmetric RSA Key:"), wxDefaultPosition, wxDLG_UNIT(this, wxSize(-1,-1)), 0);
    
    sign_window_sizer->Add(asymm_rsa_key_lbl, 0, wxALL, 5);
    
    modulus_txtctrl = new wxTextCtrl(this, wxID_ANY, wxT(""), wxDefaultPosition, wxDLG_UNIT(this, wxSize(-1,-1)), 0);
    #if wxVERSION_NUMBER >= 3000
    modulus_txtctrl->SetHint(_("Modulus (N), hexadecimal"));
    #endif
    
    sign_window_sizer->Add(modulus_txtctrl, 0, wxALL|wxEXPAND, 5);
    
    e_txtctrl = new wxTextCtrl(this, wxID_ANY, wxT("10001"), wxDefaultPosition, wxDLG_UNIT(this, wxSize(-1,-1)), 0);
    e_txtctrl->SetToolTip(_("Hexadecimal value of public exponent; default is 10001 (65537)"));
    #if wxVERSION_NUMBER >= 3000
    e_txtctrl->SetHint(_("Public exponent (e), hexadecimal; default: 65537"));
    #endif
    
    sign_window_sizer->Add(e_txtctrl, 0, wxALL|wxEXPAND, 5);
    
    d_txtctrl = new wxTextCtrl(this, wxID_ANY, wxT(""), wxDefaultPosition, wxDLG_UNIT(this, wxSize(-1,-1)), 0);
    #if wxVERSION_NUMBER >= 3000
    d_txtctrl->SetHint(_("Private exponent (d), hexadecimal"));
    #endif
    
    sign_window_sizer->Add(d_txtctrl, 0, wxALL|wxEXPAND, 5);
    
    line2 = new wxStaticLine(this, wxID_ANY, wxDefaultPosition, wxDLG_UNIT(this, wxSize(-1,-1)), wxLI_HORIZONTAL);
    
    sign_window_sizer->Add(line2, 0, wxALL|wxEXPAND, 5);
    
    signature_lbl = new wxStaticText(this, wxID_ANY, _("Signature"), wxDefaultPosition, wxDLG_UNIT(this, wxSize(-1,-1)), wxALIGN_CENTRE);
    
    sign_window_sizer->Add(signature_lbl, 0, wxALL|wxEXPAND, 5);
    
    wxFlexGridSizer* sign_verify_sizer = new wxFlexGridSizer(6, 5, 0, 0);
    sign_verify_sizer->SetFlexibleDirection( wxBOTH );
    sign_verify_sizer->SetNonFlexibleGrowMode( wxFLEX_GROWMODE_SPECIFIED );
    sign_verify_sizer->AddGrowableCol(0);
    sign_verify_sizer->AddGrowableCol(2);
    sign_verify_sizer->AddGrowableCol(4);
    
    sign_window_sizer->Add(sign_verify_sizer, 1, wxALL|wxEXPAND, 5);
    
    sign_verify_sizer->Add(0, 0, 1, wxALL, 5);
    
    sign_lb = new wxStaticText(this, wxID_ANY, _("Sign"), wxDefaultPosition, wxDLG_UNIT(this, wxSize(-1,-1)), wxALIGN_CENTRE);
    
    sign_verify_sizer->Add(sign_lb, 0, wxALL, 5);
    
    sign_verify_sizer->Add(1, 0, 1, wxALL, 5);
    
    verify_lbl = new wxStaticText(this, wxID_ANY, _("Verify"), wxDefaultPosition, wxDLG_UNIT(this, wxSize(-1,-1)), 0);
    
    sign_verify_sizer->Add(verify_lbl, 0, wxALL, 5);
    
    sign_verify_sizer->Add(0, 0, 1, wxALL, 5);
    
    sign_in_lbl = new wxStaticText(this, wxID_ANY, _("Input:"), wxDefaultPosition, wxDLG_UNIT(this, wxSize(-1,-1)), 0);
    
    sign_verify_sizer->Add(sign_in_lbl, 0, wxALL, 5);
    
    sign_verify_sizer->Add(0, 0, 1, wxALL, 5);
    
    sign_verify_sizer->Add(0, 0, 1, wxALL, 5);
    
    sign_verify_sizer->Add(0, 0, 1, wxALL, 5);
    
    verify_in_lbl = new wxStaticText(this, wxID_ANY, _("Input signature:"), wxDefaultPosition, wxDLG_UNIT(this, wxSize(-1,-1)), 0);
    
    sign_verify_sizer->Add(verify_in_lbl, 0, wxALL, 5);
    
    sign_in_txtctrl = new wxTextCtrl(this, wxID_ANY, wxT(""), wxDefaultPosition, wxDLG_UNIT(this, wxSize(-1,-1)), 0);
    #if wxVERSION_NUMBER >= 3000
    sign_in_txtctrl->SetHint(_("datoteka.txt"));
    #endif
	#ifdef SIGN_DEBUG
	sign_in_txtctrl->SetValue(_("C:/Users/mhlkv/Desktop/nos_proba/sign_in.txt"));
    #endif
    
    sign_verify_sizer->Add(sign_in_txtctrl, 0, wxALL|wxEXPAND, 5);
    
    sign_in_btn = new wxButton(this, wxID_ANY, _("Browse"), wxDefaultPosition, wxDLG_UNIT(this, wxSize(-1,-1)), 0);
    
    sign_verify_sizer->Add(sign_in_btn, 0, wxALL, 5);
    
    sign_verify_sizer->Add(0, 0, 1, wxALL, 5);
    
    verify_in_btn = new wxButton(this, wxID_ANY, _("Browse"), wxDefaultPosition, wxDLG_UNIT(this, wxSize(-1,-1)), 0);
    
    sign_verify_sizer->Add(verify_in_btn, 0, wxALL, 5);
    
    verify_in_txtctrl = new wxTextCtrl(this, wxID_ANY, wxT(""), wxDefaultPosition, wxDLG_UNIT(this, wxSize(-1,-1)), 0);
    #if wxVERSION_NUMBER >= 3000
    verify_in_txtctrl->SetHint(_("datoteka.txt/datoteka.nos"));
    #endif
	#ifdef SIGN_DEBUG
	verify_in_txtctrl->SetValue(_("C:/Users/mhlkv/Desktop/nos_proba/sign_out.txt"));
    #endif
    
    sign_verify_sizer->Add(verify_in_txtctrl, 0, wxALL|wxEXPAND, 5);
    
    sign_out_lbl = new wxStaticText(this, wxID_ANY, _("Output:"), wxDefaultPosition, wxDLG_UNIT(this, wxSize(-1,-1)), 0);
    
    sign_verify_sizer->Add(sign_out_lbl, 0, wxALL, 5);
    
    sign_verify_sizer->Add(0, 0, 1, wxALL, 5);
    
    sign_verify_sizer->Add(0, 0, 1, wxALL, 5);
    
    sign_verify_sizer->Add(0, 0, 1, wxALL, 5);
    
    verify_msg_lbl = new wxStaticText(this, wxID_ANY, _("Input message:"), wxDefaultPosition, wxDLG_UNIT(this, wxSize(-1,-1)), 0);
    
    sign_verify_sizer->Add(verify_msg_lbl, 0, wxALL, 5);
    
    sign_out_txtctrl = new wxTextCtrl(this, wxID_ANY, wxT(""), wxDefaultPosition, wxDLG_UNIT(this, wxSize(-1,-1)), 0);
    #if wxVERSION_NUMBER >= 3000
    sign_out_txtctrl->SetHint(_("datoteka.txt/datoteka.nos"));
    #endif
	#ifdef SIGN_DEBUG
	sign_out_txtctrl->SetValue(_("C:/Users/mhlkv/Desktop/nos_proba/sign_out.txt"));
    #endif
    
    sign_verify_sizer->Add(sign_out_txtctrl, 0, wxALL|wxEXPAND, 5);
    
    sign_out_btn = new wxButton(this, wxID_ANY, _("Browse"), wxDefaultPosition, wxDLG_UNIT(this, wxSize(-1,-1)), 0);
    
    sign_verify_sizer->Add(sign_out_btn, 0, wxALL, 5);
    
    sign_verify_sizer->Add(0, 0, 1, wxALL, 5);
    
    verify_msg_btn = new wxButton(this, wxID_ANY, _("Browse"), wxDefaultPosition, wxDLG_UNIT(this, wxSize(-1,-1)), 0);
    
    sign_verify_sizer->Add(verify_msg_btn, 0, wxALL, 5);
    
    verify_msg_txtctrl = new wxTextCtrl(this, wxID_ANY, wxT(""), wxDefaultPosition, wxDLG_UNIT(this, wxSize(-1,-1)), 0);
    #if wxVERSION_NUMBER >= 3000
    verify_msg_txtctrl->SetHint(_("datoteka.txt"));
    #endif
	#ifdef SIGN_DEBUG
	verify_msg_txtctrl->SetValue(_("C:/Users/mhlkv/Desktop/nos_proba/sign_in.txt"));
    #endif
    
    sign_verify_sizer->Add(verify_msg_txtctrl, 0, wxALL|wxEXPAND, 5);
    
    sign_btn = new wxButton(this, wxID_ANY, _("Sign"), wxDefaultPosition, wxDLG_UNIT(this, wxSize(-1,-1)), 0);
    
    sign_verify_sizer->Add(sign_btn, 0, wxALL|wxEXPAND, 5);
    
    sign_verify_sizer->Add(0, 0, 1, wxALL, 5);
    
    sign_verify_sizer->Add(0, 0, 1, wxALL, 5);
    
    sign_verify_sizer->Add(0, 0, 1, wxALL, 5);
    
    verify_btn = new wxButton(this, wxID_ANY, _("Verify"), wxDefaultPosition, wxDLG_UNIT(this, wxSize(-1,-1)), 0);
    
    sign_verify_sizer->Add(verify_btn, 0, wxALL|wxEXPAND, 5);
	
	this->rsa_key_rb->Bind(wxEVT_COMMAND_RADIOBOX_SELECTED, &signature_window::asymm_data_changed, this);
	this->gen_key_e_btn->Bind(wxEVT_COMMAND_BUTTON_CLICKED, &signature_window::gen_N_clicked, this);
	this->asym_nos_btn->Bind(wxEVT_COMMAND_BUTTON_CLICKED, &signature_window::asymm_data_clicked, this);
	this->sign_in_btn->Bind(wxEVT_COMMAND_BUTTON_CLICKED, &signature_window::sign_in_clicked, this);
	this->sign_out_btn->Bind(wxEVT_COMMAND_BUTTON_CLICKED, &signature_window::sign_out_clicked, this);
	this->sign_btn->Bind(wxEVT_COMMAND_BUTTON_CLICKED, &signature_window::sign_clicked, this);
	this->verify_in_btn->Bind(wxEVT_COMMAND_BUTTON_CLICKED, &signature_window::verify_in_clicked, this);
	this->verify_msg_btn->Bind(wxEVT_COMMAND_BUTTON_CLICKED, &signature_window::verify_msg_clicked, this);
	this->verify_btn->Bind(wxEVT_COMMAND_BUTTON_CLICKED, &signature_window::verify_clicked, this);
}

void signature_window::gen_N_clicked(wxCommandEvent& event)
{
	if(this->e_txtctrl->GetValue().IsEmpty())
	{
		wxMessageBox(_("Must specify a public exponent to be able to generate the other two parameters"), _("Invalid public exponent (e)"), wxOK | wxICON_ERROR, this);
		event.Skip();
		return;
	}
	try
	{	
		auto key_size = vm.rsa_key_size(this->rsa_key_rb->GetSelection());
		auto [n_str, d_str] = vm.generate_n_and_d(key_size, this->e_txtctrl->GetValue());
		
		// ChangeValue ne trigera text update event
		this->modulus_txtctrl->ChangeValue(n_str);
		this->d_txtctrl->ChangeValue(d_str);
		event.Skip();
	}
	catch(const std::runtime_error& err)
	{
//		fprintf(stderr, "%s\n", err.what());
		std::cerr << err.what() << '\n';
		wxMessageBox(wxString::FromUTF8(err.what()), _("Failed to generate private exponent and modulus"), wxOK | wxICON_ERROR, this);
		event.Skip();
	}
	

}

void signature_window::asymm_data_clicked(wxCommandEvent& event)
{
	wxFileDialog open_file_dialog(this, "Open NOS file with symmetric algorithm data", "", "", "NOS files (*.nos, *.NOS|*.nos;*.NOS|Text files (*.txt)|*.txt", wxFD_OPEN|wxFD_FILE_MUST_EXIST);
	if(open_file_dialog.ShowModal() == wxID_CANCEL)
	{
		event.Skip();
		return;
	}
	file_preview_dialog file_prev_dialog(this, _("RSA data NOS file preview"), open_file_dialog.GetPath(), existing_file_t{});
	if(file_prev_dialog.ShowModal() == wxID_CANCEL)
	{
		event.Skip();
		return;
	}
	
	auto data_opt = vm.rsa_data_from_nos(file_prev_dialog.get_file_text());
	if(!data_opt.has_value())
	{
		wxMessageBox(_("No modulus, private or public exponent found in given file"), _("No data found!"), wxICON_ERROR|wxOK, this);
	}
	else
	{
		const auto& [n, e, d] = data_opt.value();
		this->modulus_txtctrl->SetValue(n);
		this->e_txtctrl->SetValue(e);
		this->d_txtctrl->SetValue(d);
	}
	
	event.Skip();
}

void signature_window::sign_in_clicked(wxCommandEvent& event)
{
	wxFileDialog open_file_dialog(this, _("Open file"), "", "", "All files (*)|*", wxFD_OPEN|wxFD_FILE_MUST_EXIST);
	if(open_file_dialog.ShowModal() == wxID_CANCEL)
	{
		event.Skip();
		return;
	}
	
	this->sign_in_txtctrl->ChangeValue(open_file_dialog.GetPath());
	event.Skip();
}

void signature_window::verify_in_clicked(wxCommandEvent& event)
{
	wxFileDialog open_file_dialog(this, _("Open file"), "", "", "NOS files (*.nos, *.NOS)|*.nos;*.NOS|Text files (*.txt)|*.txt", wxFD_OPEN|wxFD_FILE_MUST_EXIST);
	if(open_file_dialog.ShowModal() == wxID_CANCEL)
	{
		event.Skip();
		return;
	}
	
	this->verify_in_txtctrl->ChangeValue(open_file_dialog.GetPath());
	event.Skip();
}

void signature_window::sign_out_clicked(wxCommandEvent& event)
{
	wxFileDialog open_file_dialog(this, _("Open file"), "", "", "NOS files (*.nos, *.NOS)|*.nos;*.NOS|Text files (*.txt)|*.txt", wxFD_OPEN|wxFD_FILE_MUST_EXIST);
	if(open_file_dialog.ShowModal() == wxID_CANCEL)
	{
		event.Skip();
		return;
	}
	
	this->sign_out_txtctrl->ChangeValue(open_file_dialog.GetPath());
	event.Skip();
}

void signature_window::verify_msg_clicked(wxCommandEvent& event)
{
	wxFileDialog open_file_dialog(this, _("Open file"), "", "", "All files (*)|*", wxFD_OPEN|wxFD_FILE_MUST_EXIST);
	if(open_file_dialog.ShowModal() == wxID_CANCEL)
	{
		event.Skip();
		return;
	}
	
	this->verify_msg_txtctrl->ChangeValue(open_file_dialog.GetPath());
	event.Skip();
}

void signature_window::sign_clicked(wxCommandEvent& event)
{
	const wxString& out_file_path = this->sign_out_txtctrl->GetValue();
	this->sign_out_txtctrl->Enable(false);
	
	auto _ = make_scope_exit([&event, this](){event.Skip(); this->sign_out_txtctrl->Enable();});
	
	try
	{
		
		auto sign_opt = vm.sign(this->digest_alg_rb->GetSelection(),
								this->rsa_key_rb->GetSelection(),
								this->modulus_txtctrl->GetValue(),
								this->e_txtctrl->GetValue(),
								this->d_txtctrl->GetValue(),
								this->sign_in_txtctrl->GetValue());
		if(!sign_opt.has_value())
		{
			std::cerr << "Error while trying to generate seal (NOS file)\n";
			wxMessageBox(_("Was not able to generate a NOS file, check if all the necessary fields are filled"), _("Failed NOS file generation!"), wxOK | wxICON_ERROR, this);
		}
		else
		{
			file_preview_dialog preview_dialog(this, _("Signed NOS file preview"), sign_opt.value(), generated_file_t{});
			if(preview_dialog.ShowModal() == wxID_OK)
			{
				if(out_file_path.empty())
				{
					std::cerr << "No sign output file\n";
					wxMessageBox(_("No signature NOS output file specified. The output will be discarded"), _("No output file"), wxOK | wxICON_WARNING, this);
				}
				else
				{	
					if(preview_dialog.save(out_file_path))
					{
						wxMessageBox(_("Signed data saved to file"), _("Saved!"), wxOK | wxICON_INFORMATION, this);
					}
					else
					{
						wxMessageBox(_("Failed to save generated signature file to the specified location!"), _("Failed to save file!"), wxOK | wxICON_ERROR, this);
					}
				}
			}
		}
	}
	catch(const std::runtime_error& err)
	{
		wxMessageBox(wxString::FromUTF8(err.what()), _("Failed to sign data"), wxOK | wxICON_ERROR, this);
		wxMessageBox(wxString::FromUTF8(ERR_error_string(ERR_get_error(), nullptr)), _("Failed to sign data"), wxOK | wxICON_ERROR, this);
		return;
	}
}

void signature_window::verify_clicked(wxCommandEvent& event)
{
	const wxString& out_file_path = this->verify_msg_txtctrl->GetValue();
	this->verify_msg_txtctrl->Enable(false);
	
	auto _ = make_scope_exit([&event, this](){event.Skip(); this->verify_msg_txtctrl->Enable();});
	
	try
	{
		
		auto verify_opt = vm.verify_recover(this->digest_alg_rb->GetSelection(),
										    this->rsa_key_rb->GetSelection(),
										    this->modulus_txtctrl->GetValue(),
										    this->e_txtctrl->GetValue(),
										    this->d_txtctrl->GetValue(),
										    this->verify_in_txtctrl->GetValue(),
											this->verify_msg_txtctrl->GetValue());
		if(!verify_opt.has_value())
		{
			std::cerr << "Error while trying to verify signature (NOS file)\n";
			wxMessageBox(_("Was not able to verify signature, check if all the necessary fields are filled"), _("Failed NOS file generation!"), wxOK | wxICON_ERROR, this);
		}
		else
		{
			auto [hashed_msg, org_data, valid_signature] = verify_opt.value();
			if(valid_signature)
			{
				wxMessageBox(_("The signature of the message is valid!"), _("Valid!"), wxOK | wxICON_INFORMATION, this);
			}
			else
			{
				wxMessageBox(_("The signature of the message is invalid!"), _("Invalid!"), wxOK | wxICON_STOP, this);
			}
			compare_dialog cmp_dialog(this, _("Verification B64 preview"), _("Hashed message"), _("Recovered hash"), hashed_msg, org_data, generated_file_t{});
			
			cmp_dialog.ShowModal();
		}
	}
	catch(const std::runtime_error& err)
	{
		wxMessageBox(wxString::FromUTF8(err.what()), _("Failed to verify data"), wxOK | wxICON_ERROR, this);
		wxMessageBox(wxString::FromUTF8(ERR_error_string(ERR_get_error(), nullptr)), _("Failed to verify data"), wxOK | wxICON_ERROR, this);
		return;
	}
}

void signature_window::asymm_data_changed(wxCommandEvent& event)
{
	this->vm.rsa_data_change();
}
