#ifndef FILE_PREVIEW_DIALOG_H
#define FILE_PREVIEW_DIALOG_H

#include "wx/wx.h"
#include "wx/stc/stc.h"

#include "dialog_helpers.h"

struct file_preview_dialog : wxDialog
{

	file_preview_dialog(wxWindow * parent, const wxString& title, const wxString& file_path, existing_file_t);
	file_preview_dialog(wxWindow * parent, const wxString& title, const wxString& text, generated_file_t);
//	~file_preview_dialog();
	
	wxString get_file_text() const;
	bool save(const wxString& file_name) const;
	
private:

	void init();
	
	wxPanel* txt_panel;
    wxStyledTextCtrl* txt_ctrl;
    wxButton* ok_btn;
    wxButton* cancel_btn;
	
	void ok_clicked(wxCommandEvent& event);
	void cancel_clicked(wxCommandEvent& event);

};

#endif // NOS_FILE_PREVIEW_DIALOG_H
