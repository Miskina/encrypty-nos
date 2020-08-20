#ifndef COMPARE_DIALOG_H
#define COMPARE_DIALOG_H

#include "wx/wx.h"
#include <wx/stattext.h>
#include <wx/stc/stc.h>

#include "dialog_helpers.h"

struct compare_dialog : public wxDialog
{

	compare_dialog(wxWindow * parent,
				   const wxString& title,
				   const wxString& in_lbl,
				   const wxString& out_lbl,
				   const wxString& in_path,
				   const wxString& out_path,
				   existing_file_t);
	
	compare_dialog(wxWindow * parent,
				   const wxString& title,
				   const wxString& in_lbl,
				   const wxString& out_lbl,
				   const wxString& in_txt,
				   const wxString& out_txt,
				   generated_file_t);
//	~compare_dialog();
private:
	void init(const wxString& in_lbl, const wxString& out_lbl);
	
	wxStaticText* in_label;
    wxStaticText* out_label;
    wxStyledTextCtrl* compare_ctrl_in;
    wxStyledTextCtrl* compare_ctrl_out;
    wxButton* ok_btn;
    wxButton* cancel_btn;
	
	void ok_clicked(wxCommandEvent& event);
	void cancel_clicked(wxCommandEvent& event);
	
	wxString get_in_text() const;
	wxString get_out_text() const;
	
	bool save(const wxString& file_name) const;
};

#endif // COMPARE_DIALOG_H
