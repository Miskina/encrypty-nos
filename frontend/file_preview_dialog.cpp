#include "file_preview_dialog.h"


file_preview_dialog::file_preview_dialog(wxWindow * parent, const wxString& title, const wxString& file_path, existing_file_t) : wxDialog(parent, wxID_ANY, title)
{
	
	init();
	txt_ctrl->LoadFile(file_path);

}


file_preview_dialog::file_preview_dialog(wxWindow * parent, const wxString& title, const wxString& text, generated_file_t) : wxDialog(parent, wxID_ANY, title)
{
	
	init();
	txt_ctrl->ChangeValue(text);

}

void file_preview_dialog::init()
{
	wxBoxSizer* dialog_sizer = new wxBoxSizer(wxVERTICAL);
    this->SetSizer(dialog_sizer);
    
    txt_panel = new wxPanel(this, wxID_ANY, wxDefaultPosition, wxDLG_UNIT(this, wxSize(-1,-1)), wxTAB_TRAVERSAL);
    
    dialog_sizer->Add(txt_panel, 5, wxALL|wxEXPAND, 5);
    
    wxBoxSizer* txt_sizer = new wxBoxSizer(wxVERTICAL);
    txt_panel->SetSizer(txt_sizer);
    
    txt_ctrl = new wxStyledTextCtrl(txt_panel, wxID_ANY, wxDefaultPosition, wxDLG_UNIT(txt_panel, wxSize(-1,-1)), 0);
//    txt_ctrl->Enable(false);
//	txt_ctrl->ChangeValue(text);
    // Configure the fold margin
    txt_ctrl->SetMarginType     (4, wxSTC_MARGIN_SYMBOL);
    txt_ctrl->SetMarginMask     (4, wxSTC_MASK_FOLDERS);
    txt_ctrl->SetMarginSensitive(4, true);
    txt_ctrl->SetMarginWidth    (4, 16);
    
    txt_ctrl->SetProperty(wxT("fold"),wxT("1"));
    txt_ctrl->MarkerDefine(wxSTC_MARKNUM_FOLDEROPEN,    wxSTC_MARK_ARROWDOWN);
    txt_ctrl->MarkerDefine(wxSTC_MARKNUM_FOLDER,        wxSTC_MARK_ARROW);
    txt_ctrl->MarkerDefine(wxSTC_MARKNUM_FOLDERSUB,     wxSTC_MARK_BACKGROUND);
    txt_ctrl->MarkerDefine(wxSTC_MARKNUM_FOLDERTAIL,    wxSTC_MARK_BACKGROUND);
    txt_ctrl->MarkerDefine(wxSTC_MARKNUM_FOLDEREND,     wxSTC_MARK_ARROW);
    txt_ctrl->MarkerDefine(wxSTC_MARKNUM_FOLDEROPENMID, wxSTC_MARK_ARROWDOWN);
    txt_ctrl->MarkerDefine(wxSTC_MARKNUM_FOLDERMIDTAIL, wxSTC_MARK_BACKGROUND);
    // Configure the tracker margin
    txt_ctrl->SetMarginWidth(1, 0);
    
    // Configure the symbol margin
    txt_ctrl->SetMarginType (2, wxSTC_MARGIN_SYMBOL);
    txt_ctrl->SetMarginMask (2, ~(wxSTC_MASK_FOLDERS));
    txt_ctrl->SetMarginWidth(2, 0);
    txt_ctrl->SetMarginSensitive(2, true);
    
    // Configure the line numbers margin
    int txt_ctrl_PixelWidth = 4 + 5 *txt_ctrl->TextWidth(wxSTC_STYLE_LINENUMBER, wxT("9"));
    txt_ctrl->SetMarginType(0, wxSTC_MARGIN_NUMBER);
    txt_ctrl->SetMarginWidth(0,txt_ctrl_PixelWidth);
    
    // Configure the line symbol margin
    txt_ctrl->SetMarginType(3, wxSTC_MARGIN_FORE);
    txt_ctrl->SetMarginMask(3, 0);
    txt_ctrl->SetMarginWidth(3,0);
    // Select the lexer
    txt_ctrl->SetLexer(wxSTC_LEX_NULL);
    // Set default font / styles
    txt_ctrl->StyleClearAll();
    txt_ctrl->SetWrapMode(0);
    txt_ctrl->SetIndentationGuides(0);
    txt_ctrl->SetKeyWords(0, wxT(""));
    txt_ctrl->SetKeyWords(1, wxT(""));
    txt_ctrl->SetKeyWords(2, wxT(""));
    txt_ctrl->SetKeyWords(3, wxT(""));
    txt_ctrl->SetKeyWords(4, wxT(""));
    
    txt_sizer->Add(txt_ctrl, 5, wxALL|wxEXPAND, 5);
    
    wxBoxSizer* btn_sizer = new wxBoxSizer(wxHORIZONTAL);
    
    dialog_sizer->Add(btn_sizer, 1, wxALL|wxEXPAND|wxALIGN_RIGHT, 5);
    
    ok_btn = new wxButton(this, wxID_ANY, _("OK"), wxDefaultPosition, wxDLG_UNIT(this, wxSize(-1,-1)), 0);
    
    btn_sizer->Add(ok_btn, 0, wxALL, 5);
    
    cancel_btn = new wxButton(this, wxID_ANY, _("Cancel"), wxDefaultPosition, wxDLG_UNIT(this, wxSize(-1,-1)), 0);
    
    btn_sizer->Add(cancel_btn, 0, wxALL, 5);
	
	this->ok_btn->Bind(wxEVT_COMMAND_BUTTON_CLICKED, &file_preview_dialog::ok_clicked, this);
	this->cancel_btn->Bind(wxEVT_COMMAND_BUTTON_CLICKED, &file_preview_dialog::cancel_clicked, this);
}

void file_preview_dialog::ok_clicked(wxCommandEvent& event)
{
	EndDialog(wxID_OK);
	event.Skip();
}

void file_preview_dialog::cancel_clicked(wxCommandEvent& event)
{
	EndDialog(wxID_CANCEL);
	event.Skip();
}

wxString file_preview_dialog::get_file_text() const
{
	return this->txt_ctrl->GetText();
}

bool file_preview_dialog::save(const wxString& file_name) const
{
	return this->txt_ctrl->SaveFile(file_name);
}