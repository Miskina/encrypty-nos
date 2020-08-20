#include "envelope_window.h"
#include "constants.h"
#include "file_preview_dialog.h"
#include "scope_exit.h"
//#include "wx/wfstream.h"
#include "wx/textfile.h"

#include <openssl/err.h>

#include <fstream>
#include <iostream>

#define MISKINA_DEBUG 1

wxBEGIN_EVENT_TABLE(envelope_window, wxScrolledWindow)
	EVT_RADIOBOX(constants::env_pnl::SYMM_ALOG_RB_ID, envelope_window::symm_algo_select)
	EVT_BUTTON(constants::env_pnl::ASYM_NOS_BTN_ID, envelope_window::asymm_data_clicked)
	EVT_BUTTON(constants::env_pnl::GEN_E_KEY_BTN_ID, envelope_window::gen_N_clicked)
	EVT_BUTTON(constants::env_pnl::OPEN_BTN_ID, envelope_window::open_clicked)
	EVT_BUTTON(constants::env_pnl::OPEN_IN_BTN_ID, envelope_window::open_in_clicked)
	EVT_BUTTON(constants::env_pnl::OPEN_OUT_BTN_ID, envelope_window::open_out_clicked)
	EVT_BUTTON(constants::env_pnl::RAND_IV_BTN_ID, envelope_window::rand_iv_clicked)
	EVT_BUTTON(constants::env_pnl::RAND_SYMM_KEY_BTN_ID, envelope_window::rand_symm_clicked)
	EVT_BUTTON(constants::env_pnl::SEAL_BTN_ID, envelope_window::seal_clicked)
	EVT_BUTTON(constants::env_pnl::SEAL_IN_BTN_ID, envelope_window::seal_in_clicked)
	EVT_BUTTON(constants::env_pnl::SEAL_OUT_BTN_ID, envelope_window::seal_out_clicked)
	EVT_BUTTON(constants::env_pnl::SYMM_NOS_BTN_ID, envelope_window::symm_nos_btn_clicked)
	EVT_TEXT(constants::env_pnl::D_CTRL_ID, envelope_window::asymm_data_changed)
	EVT_TEXT(constants::env_pnl::E_CTRL_ID, envelope_window::asymm_data_changed)
	EVT_TEXT(constants::env_pnl::N_CTRL_ID, envelope_window::asymm_data_changed)
wxEND_EVENT_TABLE()


envelope_window::envelope_window(wxWindow * parent, wxWindowID id) : wxScrolledWindow(parent, id, wxDefaultPosition, wxDLG_UNIT(parent, wxSize(-1, -1)), wxHSCROLL | wxVSCROLL)
{
	this->SetScrollRate(5, 5);
	
	wxBoxSizer * env_panel_sizer = new wxBoxSizer(wxVERTICAL);
	this->SetSizer(env_panel_sizer);
	
	symmc_data_lbl = new wxStaticText(this, wxID_ANY, _("Symmetric data"), wxDefaultPosition, wxDLG_UNIT(this, wxSize(-1,-1)), wxALIGN_CENTRE);
    
//    env_panel_sizer->Add(symmc_data_lbl, 0, wxALL|wxEXPAND, 5);
	env_panel_sizer->Add(symmc_data_lbl, 0, wxALL|wxEXPAND, 5);
    
    wxBoxSizer* symm_radio_sizer = new wxBoxSizer(wxHORIZONTAL);
    
//    env_panel_sizer->Add(symm_radio_sizer, 0, wxALL|wxEXPAND, 5);
    env_panel_sizer->Add(symm_radio_sizer, 0, wxALL|wxEXPAND, 5);
	
    wxArrayString symm_alg_rbArr;
    symm_alg_rbArr.Add(_("3-DES"));
    symm_alg_rbArr.Add(_("AES"));
    symm_alg_rb = new wxRadioBox(this, constants::env_pnl::SYMM_ALOG_RB_ID, _("Encryption algorithm"), wxDefaultPosition, wxDLG_UNIT(this, wxSize(-1,-1)), symm_alg_rbArr, 1, 0);
    symm_alg_rb->SetSelection(1);
    
//    symm_radio_sizer->Add(symm_alg_rb, 1, wxALL, 5);
	symm_radio_sizer->Add(symm_alg_rb, 1, wxALL, 5);
    
    wxArrayString symm_key_size_rbArr;
    symm_key_size_rbArr.Add(_("128"));
    symm_key_size_rbArr.Add(_("192"));
    symm_key_size_rbArr.Add(_("256"));
    symm_key_size_rb = new wxRadioBox(this, wxID_ANY, _("Key size"), wxDefaultPosition, wxDLG_UNIT(this, wxSize(-1,-1)), symm_key_size_rbArr, 2, 0);
    symm_key_size_rb->SetSelection(0);
    
//    symm_radio_sizer->Add(symm_key_size_rb, 1, wxALL, 5);
	symm_radio_sizer->Add(symm_key_size_rb, 1, wxALL, 5);
    
    wxArrayString symm_blck_rbArr{};
    symm_blck_rbArr.Add(_("CBC"));
    symm_blck_rbArr.Add(_("CFB"));
    symm_blck_rbArr.Add(_("OFB"));
    symm_blck_rbArr.Add(_("CTR"));
    symm_enc_type_rb = new wxRadioBox(this, wxID_ANY, _("Encryption type"), wxDefaultPosition, wxDLG_UNIT(this, wxSize(-1,-1)), symm_blck_rbArr, 2, 0);
    symm_enc_type_rb->SetSelection(0);
    
//    symm_radio_sizer->Add(symm_enc_type_rb, 1, wxALL, 5);
	symm_radio_sizer->Add(symm_enc_type_rb, 1, wxALL, 5);
    
    symm_nos_btn = new wxButton(this, constants::env_pnl::SYMM_NOS_BTN_ID, _("Symmetric data from NOS file"), wxDefaultPosition, wxDLG_UNIT(this, wxSize(-1,-1)), 0);
    
//    symm_radio_sizer->Add(symm_nos_btn, 1, wxALL|wxEXPAND, 5);
	symm_radio_sizer->Add(symm_nos_btn, 1, wxALL|wxEXPAND, 5);
    
    symm_key_lbl = new wxStaticText(this, wxID_ANY, _("Symmetric Key:"), wxDefaultPosition, wxDLG_UNIT(this, wxSize(-1,-1)), 0);
    
//    env_panel_sizer->Add(symm_key_lbl, 0, wxALL, 5);
	env_panel_sizer->Add(symm_key_lbl, 0, wxALL, 5);
    
    wxFlexGridSizer* symm_param_sizer = new wxFlexGridSizer(2, 2, 0, 0);
    symm_param_sizer->SetFlexibleDirection( wxBOTH );
    symm_param_sizer->SetNonFlexibleGrowMode( wxFLEX_GROWMODE_SPECIFIED );
    symm_param_sizer->AddGrowableCol(0);
    
//    env_panel_sizer->Add(symm_param_sizer, 0, wxALL|wxEXPAND, 5);
	env_panel_sizer->Add(symm_param_sizer, 0, wxALL|wxEXPAND, 5);
    
    symm_key_txtctrl = new wxTextCtrl(this, wxID_ANY, wxT(""), wxDefaultPosition, wxDLG_UNIT(this, wxSize(-1,-1)), 0);
    #if wxVERSION_NUMBER >= 3000
    symm_key_txtctrl->SetHint(_("Symmetric key, hexadecimal"));
    #endif
    
//    symm_param_sizer->Add(symm_key_txtctrl, 0, wxALL|wxEXPAND, 5);
	symm_param_sizer->Add(symm_key_txtctrl, 0, wxALL|wxEXPAND, 5);
    
    rnd_symm_key_btn = new wxButton(this, constants::env_pnl::RAND_SYMM_KEY_BTN_ID, _("Generate random"), wxDefaultPosition, wxDLG_UNIT(this, wxSize(-1,-1)), 0);
    
//    symm_param_sizer->Add(rnd_symm_key_btn, 0, wxALL, 5);
	symm_param_sizer->Add(rnd_symm_key_btn, 0, wxALL, 5);
    
    iv_txtctrl = new wxTextCtrl(this, wxID_ANY, wxT(""), wxDefaultPosition, wxDLG_UNIT(this, wxSize(-1,-1)), 0);
    #if wxVERSION_NUMBER >= 3000
    iv_txtctrl->SetHint(_("Initializiation vector, hexadecimal"));
    #endif
    
    symm_param_sizer->Add(iv_txtctrl, 0, wxALL|wxEXPAND, 5);
//	symm_param_sizer->Add(iv_txtctrl, 0, wxALL|wxEXPAND, 5);
    
    rand_iv_btn = new wxButton(this, constants::env_pnl::RAND_IV_BTN_ID, _("Generate random"), wxDefaultPosition, wxDLG_UNIT(this, wxSize(-1,-1)), 0);
    
//    symm_param_sizer->Add(rand_iv_btn, 0, wxALL, 5);
	symm_param_sizer->Add(rand_iv_btn, 0, wxALL, 5);
    
    line1 = new wxStaticLine(this, wxID_ANY, wxDefaultPosition, wxDLG_UNIT(this, wxSize(-1,-1)), wxLI_HORIZONTAL);
    
//    env_panel_sizer->Add(line1, 0, wxALL|wxEXPAND, 5);
	env_panel_sizer->Add(line1, 0, wxALL|wxEXPAND, 5);
    
    asymm_lbl = new wxStaticText(this, wxID_ANY, _("Asymmetric data"), wxDefaultPosition, wxDLG_UNIT(this, wxSize(-1,-1)), wxALIGN_CENTRE);
    
//    env_panel_sizer->Add(asymm_lbl, 0, wxALL|wxEXPAND, 5);
	env_panel_sizer->Add(asymm_lbl, 0, wxALL|wxEXPAND, 5);
    
    wxBoxSizer* asymm_key_sizer = new wxBoxSizer(wxHORIZONTAL);
    
//    env_panel_sizer->Add(asymm_key_sizer, 0, wxALL|wxEXPAND, 5);
	env_panel_sizer->Add(asymm_key_sizer, 0, wxALL|wxEXPAND, 5);
    
    wxArrayString rsa_key_rbArr;
    rsa_key_rbArr.Add(_("512"));
    rsa_key_rbArr.Add(_("1024"));
    rsa_key_rbArr.Add(_("2048"));
    rsa_key_rbArr.Add(_("4096"));
    rsa_key_rb = new wxRadioBox(this, wxID_ANY, _("Asymetric(RSA) Key Size"), wxDefaultPosition, wxDLG_UNIT(this, wxSize(-1,-1)), rsa_key_rbArr, 2, 0);
    rsa_key_rb->SetSelection(0);
    
	asymm_key_sizer->Add(rsa_key_rb, 1, wxALL, 5);
//    asymm_key_sizer->Add(rsa_key_rb, 1, wxALL, 5);
    
    gen_key_e_btn = new wxButton(this, constants::env_pnl::GEN_E_KEY_BTN_ID, _("Generate from key size and public exponent"), wxDefaultPosition, wxDLG_UNIT(this, wxSize(-1,-1)), 0);
    
//    asymm_key_sizer->Add(gen_key_e_btn, 2, wxALL|wxEXPAND, 5);
	asymm_key_sizer->Add(gen_key_e_btn, 2, wxALL|wxEXPAND, 5);
    
    asym_nos_btn = new wxButton(this, constants::env_pnl::ASYM_NOS_BTN_ID, _("Asymmetric data from NOS file"), wxDefaultPosition, wxDLG_UNIT(this, wxSize(-1,-1)), 0);
    
//    asymm_key_sizer->Add(asym_nos_btn, 1, wxALL|wxEXPAND, 5);
	asymm_key_sizer->Add(asym_nos_btn, 1, wxALL|wxEXPAND, 5);
    
    asymm_rsa_key_lbl = new wxStaticText(this, wxID_ANY, _("Asymmetric RSA Key:"), wxDefaultPosition, wxDLG_UNIT(this, wxSize(-1,-1)), 0);
    
//    env_panel_sizer->Add(asymm_rsa_key_lbl, 0, wxALL, 5);
	env_panel_sizer->Add(asymm_rsa_key_lbl, 0, wxALL, 5);
    
    modulus_txtctrl = new wxTextCtrl(this, constants::env_pnl::N_CTRL_ID, wxT(""), wxDefaultPosition, wxDLG_UNIT(this, wxSize(-1,-1)), 0);
    #if wxVERSION_NUMBER >= 3000
    modulus_txtctrl->SetHint(_("Modulus (n), hexadecimal"));
    #endif
    
//    env_panel_sizer->Add(modulus_txtctrl, 0, wxALL|wxEXPAND, 5);
	env_panel_sizer->Add(modulus_txtctrl, 0, wxALL|wxEXPAND, 5);
    
    e_txtctrl = new wxTextCtrl(this, constants::env_pnl::E_CTRL_ID, wxT(""), wxDefaultPosition, wxDLG_UNIT(this, wxSize(-1,-1)), 0);
    #if wxVERSION_NUMBER >= 3000
    e_txtctrl->SetHint(_("Public exponent (e), hexadecimal; default: 65537"));
    #endif
	e_txtctrl->SetValue(_("10001"));
	e_txtctrl->SetToolTip(_("Hexadecimal value of public exponent; default is 10001 (65537)"));
    
//    env_panel_sizer->Add(e_txtctrl, 0, wxALL|wxEXPAND, 5);
	env_panel_sizer->Add(e_txtctrl, 0, wxALL|wxEXPAND, 5);
	
	d_txtctrl = new wxTextCtrl(this, constants::env_pnl::D_CTRL_ID, wxT(""), wxDefaultPosition, wxDLG_UNIT(this, wxSize(-1,-1)), 0);
    #if wxVERSION_NUMBER >= 3000
    d_txtctrl->SetHint(_("Private exponent (d), hexadecimal"));
    #endif
    
    env_panel_sizer->Add(d_txtctrl, 0, wxALL|wxEXPAND, 5);
    
    line2 = new wxStaticLine(this, wxID_ANY, wxDefaultPosition, wxDLG_UNIT(this, wxSize(-1,-1)), wxLI_HORIZONTAL);
    
//    env_panel_sizer->Add(line2, 0, wxALL|wxEXPAND, 5);
	env_panel_sizer->Add(line2, 0, wxALL|wxEXPAND, 5);
	
	envelope_lbl = new wxStaticText(this, wxID_ANY, _("Envelope"), wxDefaultPosition, wxDLG_UNIT(this, wxSize(-1,-1)), wxALIGN_CENTRE);
    
    env_panel_sizer->Add(envelope_lbl, 0, wxALL|wxEXPAND, 5);
    
    wxFlexGridSizer* seal_open_sizer = new wxFlexGridSizer(6, 5, 0, 0);
    seal_open_sizer->SetFlexibleDirection( wxBOTH );
    seal_open_sizer->SetNonFlexibleGrowMode( wxFLEX_GROWMODE_SPECIFIED );
    seal_open_sizer->AddGrowableCol(0);
    seal_open_sizer->AddGrowableCol(2);
    seal_open_sizer->AddGrowableCol(4);
    
    env_panel_sizer->Add(seal_open_sizer, 1, wxALL|wxEXPAND, 5);
    
    seal_open_sizer->Add(0, 0, 1, wxALL, 5);
    
    seal_lbl = new wxStaticText(this, wxID_ANY, _("Seal"), wxDefaultPosition, wxDLG_UNIT(this, wxSize(-1,-1)), wxALIGN_CENTRE);
    
    seal_open_sizer->Add(seal_lbl, 0, wxALL, 5);
    
    seal_open_sizer->Add(1, 0, 1, wxALL, 5);
    
    open_lbl = new wxStaticText(this, wxID_ANY, _("Open"), wxDefaultPosition, wxDLG_UNIT(this, wxSize(-1,-1)), 0);
    
    seal_open_sizer->Add(open_lbl, 0, wxALL, 5);
    
    seal_open_sizer->Add(0, 0, 1, wxALL, 5);
    
    seal_in_lbl = new wxStaticText(this, wxID_ANY, _("Input:"), wxDefaultPosition, wxDLG_UNIT(this, wxSize(-1,-1)), 0);
    
    seal_open_sizer->Add(seal_in_lbl, 0, wxALL, 5);
    
    seal_open_sizer->Add(0, 0, 1, wxALL, 5);
    
    seal_open_sizer->Add(0, 0, 1, wxALL, 5);
    
    seal_open_sizer->Add(0, 0, 1, wxALL, 5);
    
    open_in_lbl = new wxStaticText(this, wxID_ANY, _("Input:"), wxDefaultPosition, wxDLG_UNIT(this, wxSize(-1,-1)), 0);
    
    seal_open_sizer->Add(open_in_lbl, 0, wxALL, 5);
    
    seal_in_txtctrl = new wxTextCtrl(this, wxID_ANY, wxT(""), wxDefaultPosition, wxDLG_UNIT(this, wxSize(-1,-1)), 0);
    #if wxVERSION_NUMBER >= 3000
    seal_in_txtctrl->SetHint(_("C:/..."));
    #endif
	#ifdef MISKINA_DEBUG
	seal_in_txtctrl->SetValue(_("C:/Users/mhlkv/Desktop/nos_proba/env_in.txt"));
    #endif
    seal_open_sizer->Add(seal_in_txtctrl, 0, wxALL|wxEXPAND, 5);
    
    seal_in_btn = new wxButton(this, constants::env_pnl::SEAL_IN_BTN_ID, _("Browse"), wxDefaultPosition, wxDLG_UNIT(this, wxSize(-1,-1)), 0);
    
    seal_open_sizer->Add(seal_in_btn, 0, wxALL, 5);
    
    seal_open_sizer->Add(0, 0, 1, wxALL, 5);
    
    open_in_btn = new wxButton(this, constants::env_pnl::OPEN_IN_BTN_ID, _("Browse"), wxDefaultPosition, wxDLG_UNIT(this, wxSize(-1,-1)), 0);
    
    seal_open_sizer->Add(open_in_btn, 0, wxALL, 5);
    
    open_in_txtctrl = new wxTextCtrl(this, wxID_ANY, wxT("envelope.nos"), wxDefaultPosition, wxDLG_UNIT(this, wxSize(-1,-1)), 0);
    #if wxVERSION_NUMBER >= 3000
    open_in_txtctrl->SetHint(_("NOS file"));
    #endif
	#ifdef MISKINA_DEBUG
	open_in_txtctrl->SetValue(_("C:/Users/mhlkv/Desktop/nos_proba/env_out.txt"));
    #endif
    seal_open_sizer->Add(open_in_txtctrl, 0, wxALL|wxEXPAND, 5);
    
    seal_out_lbl = new wxStaticText(this, wxID_ANY, _("Output:"), wxDefaultPosition, wxDLG_UNIT(this, wxSize(-1,-1)), 0);
    
    seal_open_sizer->Add(seal_out_lbl, 0, wxALL, 5);
    
    seal_open_sizer->Add(0, 0, 1, wxALL, 5);
    
    seal_open_sizer->Add(0, 0, 1, wxALL, 5);
    
    seal_open_sizer->Add(0, 0, 1, wxALL, 5);
    
    open_out_lbl = new wxStaticText(this, wxID_ANY, _("Output:"), wxDefaultPosition, wxDLG_UNIT(this, wxSize(-1,-1)), 0);
    
    seal_open_sizer->Add(open_out_lbl, 0, wxALL, 5);
    
    seal_out_txtctrl = new wxTextCtrl(this, wxID_ANY, wxT("enevlope.nos"), wxDefaultPosition, wxDLG_UNIT(this, wxSize(-1,-1)), 0);
    #if wxVERSION_NUMBER >= 3000
    seal_out_txtctrl->SetHint(_("NOS file"));
    #endif
	#ifdef MISKINA_DEBUG
	seal_out_txtctrl->SetValue(_("C:/Users/mhlkv/Desktop/nos_proba/env_out.txt"));
	#endif
    seal_open_sizer->Add(seal_out_txtctrl, 0, wxALL|wxEXPAND, 5);
    
    seal_out_btn = new wxButton(this, constants::env_pnl::SEAL_OUT_BTN_ID, _("Browse"), wxDefaultPosition, wxDLG_UNIT(this, wxSize(-1,-1)), 0);
    
    seal_open_sizer->Add(seal_out_btn, 0, wxALL, 5);
    
    seal_open_sizer->Add(0, 0, 1, wxALL, 5);
    
    open_out_btn = new wxButton(this, constants::env_pnl::OPEN_OUT_BTN_ID, _("Browse"), wxDefaultPosition, wxDLG_UNIT(this, wxSize(-1,-1)), 0);
    
    seal_open_sizer->Add(open_out_btn, 0, wxALL, 5);
    
    open_out_txtctrl = new wxTextCtrl(this, wxID_ANY, wxT(""), wxDefaultPosition, wxDLG_UNIT(this, wxSize(-1,-1)), 0);
    #if wxVERSION_NUMBER >= 3000
    open_out_txtctrl->SetHint(_("C:/..."));
    #endif
    
    seal_open_sizer->Add(open_out_txtctrl, 0, wxALL|wxEXPAND, 5);
    
    seal_btn = new wxButton(this, constants::env_pnl::SEAL_BTN_ID, _("Seal"), wxDefaultPosition, wxDLG_UNIT(this, wxSize(-1,-1)), 0);
    
    seal_open_sizer->Add(seal_btn, 0, wxALL|wxEXPAND, 5);
    
    seal_open_sizer->Add(0, 0, 1, wxALL, 5);
    
    seal_open_sizer->Add(0, 0, 1, wxALL, 5);
    
    seal_open_sizer->Add(0, 0, 1, wxALL, 5);
    
    open_btn = new wxButton(this, constants::env_pnl::OPEN_BTN_ID, _("Open"), wxDefaultPosition, wxDLG_UNIT(this, wxSize(-1,-1)), 0);
    
    seal_open_sizer->Add(open_btn, 0, wxALL|wxEXPAND, 5);
}



void envelope_window::symm_algo_select(wxCommandEvent& event)
{
	const int aes_selected = this->symm_alg_rb->GetSelection();
	for(unsigned int i = 0; i < this->symm_key_size_rb->GetCount(); ++i)
	{
		this->symm_key_size_rb->Enable(aes_selected, i);
	}
	
	if(!aes_selected && this->symm_enc_type_rb->GetSelection() == this->symm_enc_type_rb->GetCount() - 1)
	{
		this->symm_enc_type_rb->SetSelection(0);
	}
	this->symm_enc_type_rb->Enable(aes_selected, this->symm_enc_type_rb->GetCount() - 1);
	event.Skip();
}

void envelope_window::symm_nos_btn_clicked(wxCommandEvent& event)
{
	wxFileDialog open_file_dialog(this, "Open NOS file with symmetric algorithm data", "", "", "NOS files (*.nos, *.NOS|*.nos;*.NOS|Text files (*.txt)|*.txt", wxFD_OPEN|wxFD_FILE_MUST_EXIST);
	if(open_file_dialog.ShowModal() == wxID_CANCEL)
	{
		event.Skip();
		return;
	}

	file_preview_dialog file_prev_dialog(this, _("Symmetric data NOS file preview"), open_file_dialog.GetPath(), existing_file_t{});
	if(file_prev_dialog.ShowModal() == wxID_CANCEL)
	{
		event.Skip();
		return;
	}
	
	auto key_iv_pair = vm.symm_key_and_iv_from_nos(file_prev_dialog.get_file_text());
	if(!key_iv_pair.has_value())
	{
		wxMessageBox(_("No symmetric key or initializiation vector found in given file"), _("No data found!"), wxICON_ERROR|wxOK, this);
	}
	else
	{
		const auto& [key, iv] = key_iv_pair.value();
		this->symm_key_txtctrl->SetValue(key);
		this->iv_txtctrl->SetValue(iv);
	}
		
	
	event.Skip();
}

void envelope_window::rand_symm_clicked(wxCommandEvent& event)
{
	const int alg_idx = this->symm_alg_rb->GetSelection();
	const int key_size_idx = this->symm_key_size_rb->GetSelection();
	std::size_t key_size = vm.symm_key_size(alg_idx, key_size_idx);
	this->symm_key_txtctrl->SetValue(vm.rand_hex_of_size(key_size));
	event.Skip();
}

void envelope_window::rand_iv_clicked(wxCommandEvent& event)
{
	// index 0 = 3-DES, index 1 = AES
	int alg = this->symm_alg_rb->GetSelection();
	this->iv_txtctrl->SetValue(vm.rand_hex_of_size(64 + alg * 64));
	event.Skip();
}

void envelope_window::gen_N_clicked(wxCommandEvent& event)
{
	if(this->e_txtctrl->GetValue().IsEmpty())
	{
		wxMessageBox(_("Must specify a public exponent to be able to generate the other two parameters"), _("Invalid public exponent (e)"), wxOK | wxICON_ERROR, this);
		event.Skip();
		return;
	}
	const int index = this->rsa_key_rb->GetSelection();
	std::size_t key_size = vm.rsa_key_size(index);
	std::cout << "Envelope panel: using key size (" << key_size << ") and public exponent (e) to generate necessary RSA data...\n";
	try
	{		
		auto [n_str, d_str] = vm.generate_n_and_d(key_size, this->e_txtctrl->GetValue());
		
		// ChangeValue ne trigera text update event
		this->modulus_txtctrl->ChangeValue(n_str);
		this->d_txtctrl->ChangeValue(d_str);
	}
	catch(const std::runtime_error& err)
	{
//		fprintf(stderr, "%s\n", err.what());
		std::cerr << err.what() << '\n';
//		std::cout << err.what() << '\n';
	}
	event.Skip();
}

void envelope_window::asymm_data_clicked(wxCommandEvent& event)
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

void envelope_window::seal_in_clicked(wxCommandEvent& event)
{
	wxFileDialog open_file_dialog(this, _("Open file"), "", "", "All files (*)|*", wxFD_OPEN|wxFD_FILE_MUST_EXIST);
	if(open_file_dialog.ShowModal() == wxID_CANCEL)
	{
		event.Skip();
		return;
	}
	
	this->seal_in_txtctrl->ChangeValue(open_file_dialog.GetPath());
	event.Skip();
}

void envelope_window::open_in_clicked(wxCommandEvent& event)
{
	wxFileDialog open_file_dialog(this, _("Open file"), "", "", "NOS files (*.nos, *.NOS)|*.nos;*.NOS|Text files (*.txt)|*.txt", wxFD_OPEN|wxFD_FILE_MUST_EXIST);
	if(open_file_dialog.ShowModal() == wxID_CANCEL)
	{
		event.Skip();
		return;
	}
	
	this->open_in_txtctrl->ChangeValue(open_file_dialog.GetPath());
	event.Skip();
}

void envelope_window::seal_out_clicked(wxCommandEvent& event)
{
	wxFileDialog open_file_dialog(this, _("Open file"), "", "", "NOS files (*.nos, *.NOS)|*.nos;*.NOS|Text files (*.txt)|*.txt", wxFD_OPEN|wxFD_FILE_MUST_EXIST);
	if(open_file_dialog.ShowModal() == wxID_CANCEL)
	{
		event.Skip();
		return;
	}
	
	this->seal_out_txtctrl->ChangeValue(open_file_dialog.GetPath());
	event.Skip();
}

void envelope_window::open_out_clicked(wxCommandEvent& event)
{
	wxFileDialog open_file_dialog(this, _("Open file"), "", "", "Text files (*.txt)|*.txt", wxFD_OPEN|wxFD_FILE_MUST_EXIST);	
	if(open_file_dialog.ShowModal() == wxID_CANCEL)
	{
		event.Skip();
		return;
	}
	
	this->open_out_txtctrl->ChangeValue(open_file_dialog.GetPath());
	event.Skip();
}

void envelope_window::seal_clicked(wxCommandEvent& event)
{
	const wxString& out_file_path = this->seal_out_txtctrl->GetValue();
	this->seal_out_txtctrl->Enable(false);
	
	auto _ = make_scope_exit([&event, this](){event.Skip(); this->seal_out_txtctrl->Enable();});
	
	try
	{
		
	
		auto crypt_file_opt = vm.seal(this->seal_in_txtctrl->GetValue(),
										 this->symm_alg_rb->GetSelection(),
										 this->symm_key_size_rb->GetSelection(),
										 this->symm_enc_type_rb->GetSelection(),
										 this->symm_key_txtctrl->GetValue(),
										 this->iv_txtctrl->GetValue(),
										 this->rsa_key_rb->GetSelection(),
										 this->modulus_txtctrl->GetValue(),
										 this->e_txtctrl->GetValue(),
										 this->d_txtctrl->GetValue());
	
		if(!crypt_file_opt.has_value())
		{
			std::cerr << "Error while trying to generate seal (NOS file)\n";
			wxMessageBox(_("Was not able to generate a NOS file, check if all the necessary fields are filled"), _("Failed NOS file generation!"), wxOK | wxICON_ERROR, this);
		}
		else
		{
			file_preview_dialog preview_dialog(this, _("Sealed NOS file preview"), crypt_file_opt.value(), generated_file_t{});
			if(preview_dialog.ShowModal() == wxID_OK)
			{
				if(out_file_path.empty())
				{
					std::cerr << "No seal output file\n";
					wxMessageBox(_("No seal envelope output file specified. The output will be discarded"), _("No output file"), wxOK | wxICON_WARNING, this);
				}
				else
				{	
					if(preview_dialog.save(out_file_path))
					{
						wxMessageBox(_("Sealed data saved to file"), _("Saved!"), wxOK | wxICON_INFORMATION, this);
					}
					else
					{
						wxMessageBox(_("Failed to save generated sealed envelope file to the specified location!"), _("Failed to save file!"), wxOK | wxICON_ERROR, this);
					}
				}
				
			}
		}
	}
	catch(const std::runtime_error& err)
	{
		wxMessageBox(wxString::FromUTF8(err.what()), _("Failed to seal envelope"), wxOK | wxICON_ERROR, this);
		return;
	}
}

void envelope_window::open_clicked(wxCommandEvent& event)
{
	const wxString& out_file_path = this->open_out_txtctrl->GetValue();
	this->open_out_txtctrl->Enable(false);
	auto _ = make_scope_exit([&event, this](){event.Skip(); this->open_out_txtctrl->Enable();});
	
	try
	{
		auto msg_opt = this->vm.open(this->open_in_txtctrl->GetValue(),
										 this->symm_alg_rb->GetSelection(),
										 this->symm_key_size_rb->GetSelection(),
										 this->symm_enc_type_rb->GetSelection(),
										 this->iv_txtctrl->GetValue(),
										 this->rsa_key_rb->GetSelection(),
										 this->modulus_txtctrl->GetValue(),
										 this->e_txtctrl->GetValue(),
										 this->d_txtctrl->GetValue());
	
	
		if(!msg_opt.has_value())
		{
			std::cerr << "Error while trying to open envelope (NOS file)\n";
			wxMessageBox(_("Was not able to open envelope in NOS file, check if all the necessary fields are filled and the file is valid"), _("Failed NOS file read!"), wxOK | wxICON_ERROR, this);
		}
		else
		{
			file_preview_dialog preview_dialog(this, _("Opened NOS file preview"), msg_opt.value(), generated_file_t{});
			if(preview_dialog.ShowModal() == wxID_OK)
			{
				if(out_file_path.empty())
				{
					std::cerr << "No opened envelope data output file\n";
					wxMessageBox(_("No opened envelope output file specified. The output will be discarded"), _("No output file"), wxOK | wxICON_WARNING, this);
				}
				else
				{				
					if(preview_dialog.save(out_file_path))
					{
						wxMessageBox(_("Opened data saved to file"), _("Saved!"), wxOK | wxICON_INFORMATION, this);
					}
					else
					{
						wxMessageBox(_("Failed to save data from opened envelope file to the specified location!"), _("Failed to save file!"), wxOK | wxICON_ERROR, this);
					}
				}
				
			}
		}
	
	}
	catch(const std::runtime_error& err)
	{
		wxMessageBox(wxString::FromUTF8(err.what()), _("Failed to open envelope"), wxOK | wxICON_ERROR, this);
		wxMessageBox(wxString::FromUTF8(ERR_error_string(ERR_get_error(), nullptr)), _("Failed to open envelope"), wxOK | wxICON_ERROR, this);
		return;
	}
	
}

void envelope_window::asymm_data_changed(wxCommandEvent& event)
{
	vm.rsa_data_change();
	event.Skip();
}
