#ifndef ENVELOPE_WINDOW_H
#define ENVELOPE_WINDOW_H

#include "wx/wx.h"
#include "wx/statline.h"

#include "../vm/env_vm.h"


struct envelope_window : public wxScrolledWindow
{
	envelope_window(wxWindow * parent, wxWindowID id);
	
private:
	
	wxScrolledWindow * scrolled_container;
	wxStaticText* symmc_data_lbl;
    wxRadioBox* symm_alg_rb;
    wxRadioBox* symm_key_size_rb;
    wxRadioBox* symm_enc_type_rb;
    wxButton* symm_nos_btn;
    wxStaticText* symm_key_lbl;
    wxTextCtrl* symm_key_txtctrl;
    wxButton* rnd_symm_key_btn;
    wxTextCtrl* iv_txtctrl;
    wxButton* rand_iv_btn;
    wxStaticLine* line1;
    wxStaticText* asymm_lbl;
    wxRadioBox* rsa_key_rb;
    wxButton* gen_key_e_btn;
    wxButton* asym_nos_btn;
    wxStaticText* asymm_rsa_key_lbl;
    wxTextCtrl* modulus_txtctrl;
    wxTextCtrl* e_txtctrl;
	wxTextCtrl* d_txtctrl;
    wxStaticLine* line2;
    wxStaticText* envelope_lbl;
    wxStaticText* seal_lbl;
    wxStaticText* open_lbl;
    wxStaticText* seal_in_lbl;
    wxStaticText* open_in_lbl;
    wxTextCtrl* seal_in_txtctrl;
    wxButton* seal_in_btn;
    wxButton* open_in_btn;
    wxTextCtrl* open_in_txtctrl;
    wxStaticText* seal_out_lbl;
    wxStaticText* open_out_lbl;
    wxTextCtrl* seal_out_txtctrl;
    wxButton* seal_out_btn;
    wxButton* open_out_btn;
    wxTextCtrl* open_out_txtctrl;
    wxButton* seal_btn;
    wxButton* open_btn;
	
	env_vm vm{};
	
	
	void symm_algo_select(wxCommandEvent& event);
    void symm_nos_btn_clicked(wxCommandEvent& event);
    void rand_symm_clicked(wxCommandEvent& event);
    void rand_iv_clicked(wxCommandEvent& event);
    void gen_N_clicked(wxCommandEvent& event);
    void asymm_data_clicked(wxCommandEvent& event);
    void seal_in_clicked(wxCommandEvent& event);
    void open_in_clicked(wxCommandEvent& event);
    void seal_out_clicked(wxCommandEvent& event);
    void open_out_clicked(wxCommandEvent& event);
    void seal_clicked(wxCommandEvent& event);
    void open_clicked(wxCommandEvent& event);
	void asymm_data_changed(wxCommandEvent& event);
	
	wxDECLARE_EVENT_TABLE();
	
};

#endif // ENVELOPE_PANEL_H
