#ifndef SEAL_WINDOW_H
#define SEAL_WINDOW_H

#include "wx/wx.h"
#include "wx/statline.h"

#include "../vm/seal_vm.h"

struct seal_window : public wxScrolledWindow
{

	seal_window(wxWindow * parent, wxWindowID id);
	
private:
	wxRadioBox* digest_alg_rb;
    wxStaticLine* line1;
    wxStaticText* symmc_data_lb;
    wxRadioBox* symm_alg_rb;
    wxRadioBox* symm_key_size_rb;
    wxRadioBox* symm_blck_rb;
    wxButton* symm_nos_btn;
    wxStaticText* symm_key_lbl;
    wxTextCtrl* symm_key_txtctrl;
    wxButton* rnd_symm_key_btn;
    wxTextCtrl* iv_txtctrl;
    wxButton* rand_iv_btn;
    wxStaticLine* line2;
    wxStaticText* asymm_lbl;
    wxRadioBox* rsa_key_rb;
    wxButton* gen_key_e_btn;
    wxButton* asym_nos_btn;
    wxStaticText* asymm_rsa_key_lbl;
    wxTextCtrl* modulus_txtctrl;
    wxTextCtrl* e_txtctrl;
    wxTextCtrl* d_txtctrl;
    wxStaticLine* line3;
    wxStaticText* digital_seal_lbl;
    wxStaticText* seal_lbl;
    wxStaticText* unseal_lbl;
    wxStaticText* seal_in_lbl;
    wxStaticText* unseal_in_lbl;
    wxTextCtrl* seal_in_txtctrl;
    wxButton* seal_in_btn;
    wxButton* unseal_in_btn;
    wxTextCtrl* unseal_in_txtctrl;
    wxStaticText* seal_out_lbl;
    wxStaticText* unseal_out_lbl;
    wxTextCtrl* seal_out_txtctrl;
    wxButton* seal_out_btn;
    wxButton* unseal_out_btn;
    wxTextCtrl* unseal_out_txtctrl;
    wxButton* seal_btn;
    wxButton* unseal_btn;
	
	seal_vm vm{};
	
	void symm_algo_select(wxCommandEvent& event);
    void symm_nos_btn_clicked(wxCommandEvent& event);
    void rand_symm_clicked(wxCommandEvent& event);
    void rand_iv_clicked(wxCommandEvent& event);
	void gen_N_clicked(wxCommandEvent& event);
    void asymm_data_clicked(wxCommandEvent& event);
    void seal_in_clicked(wxCommandEvent& event);
    void unseal_in_clicked(wxCommandEvent& event);
    void seal_out_clicked(wxCommandEvent& event);
    void unseal_out_clicked(wxCommandEvent& event);
    void seal_clicked(wxCommandEvent& event);
    void unseal_clicked(wxCommandEvent& event);
	void asymm_data_changed(wxCommandEvent& event);
};

#endif // SEAL_WINDOW_H
