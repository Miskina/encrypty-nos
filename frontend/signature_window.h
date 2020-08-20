#ifndef SIGNATURE_WINDOW_H
#define SIGNATURE_WINDOW_H

#include "wx/wx.h"
#include "wx/statline.h"

#include "../vm/sign_vm.h"

struct signature_window : public wxScrolledWindow
{

	signature_window(wxWindow * parent, wxWindowID id);
//	~signature_window();
	
private:
	wxRadioBox* digest_alg_rb;
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
    wxStaticText* signature_lbl;
    wxStaticText* sign_lb;
    wxStaticText* verify_lbl;
    wxStaticText* sign_in_lbl;
    wxStaticText* verify_in_lbl;
    wxTextCtrl* sign_in_txtctrl;
    wxButton* sign_in_btn;
    wxButton* verify_in_btn;
    wxTextCtrl* verify_in_txtctrl;
    wxStaticText* sign_out_lbl;
    wxStaticText* verify_msg_lbl;
    wxTextCtrl* sign_out_txtctrl;
    wxButton* sign_out_btn;
    wxButton* verify_msg_btn;
    wxTextCtrl* verify_msg_txtctrl;
    wxButton* sign_btn;
    wxButton* verify_btn;
	
	sign_vm vm{};
	
	void gen_N_clicked(wxCommandEvent& event);
    void asymm_data_clicked(wxCommandEvent& event);
    void sign_in_clicked(wxCommandEvent& event);
    void verify_in_clicked(wxCommandEvent& event);
    void sign_out_clicked(wxCommandEvent& event);
    void verify_msg_clicked(wxCommandEvent& event);
    void sign_clicked(wxCommandEvent& event);
    void verify_clicked(wxCommandEvent& event);
	void asymm_data_changed(wxCommandEvent& event);
};

#endif // SIGNATURE_WINDOW_H
