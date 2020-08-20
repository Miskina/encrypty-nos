#include "compare_dialog.h"



compare_dialog::compare_dialog(wxWindow * parent,
							   const wxString& title,
							   const wxString& in_lbl,
							   const wxString& out_lbl,
							   const wxString& in_path,
							   const wxString& out_path,
							   existing_file_t) : wxDialog(parent, wxID_ANY, title, wxDefaultPosition, wxSize(800, 600))
{
   init(in_lbl, out_lbl);
   this->compare_ctrl_in->LoadFile(in_path);
   this->compare_ctrl_out->LoadFile(out_path);
} 

compare_dialog::compare_dialog(wxWindow * parent,
							   const wxString& title,
							   const wxString& in_lbl,
							   const wxString& out_lbl,
							   const wxString& in_txt,
							   const wxString& out_txt,
							   generated_file_t) : wxDialog(parent, wxID_ANY, title, wxDefaultPosition, wxSize(800, 600))
{
   init(in_lbl, out_lbl);
   this->compare_ctrl_in->ChangeValue(in_txt);
   this->compare_ctrl_out->ChangeValue(out_txt);
}

void compare_dialog::init(const wxString& in_lbl, const wxString& out_lbl)
{
	 wxFlexGridSizer* dialog_sizer = new wxFlexGridSizer(3, 2, 0, 0);
    dialog_sizer->SetFlexibleDirection(wxBOTH);
    dialog_sizer->SetNonFlexibleGrowMode(wxFLEX_GROWMODE_SPECIFIED);
    dialog_sizer->AddGrowableCol(0);
    dialog_sizer->AddGrowableCol(1);
    dialog_sizer->AddGrowableRow(1);
    this->SetSizer(dialog_sizer);

    in_label = new wxStaticText(this, wxID_ANY, in_lbl, wxDefaultPosition, wxDLG_UNIT(this, wxSize(-1, -1)), 0);

    dialog_sizer->Add(in_label, 0, wxALL, 5);

    out_label = new wxStaticText(this, wxID_ANY, out_lbl, wxDefaultPosition, wxDLG_UNIT(this, wxSize(-1, -1)), 0);

    dialog_sizer->Add(out_label, 0, wxALL, 5);

    compare_ctrl_in = new wxStyledTextCtrl(this, wxID_ANY, wxDefaultPosition, wxDLG_UNIT(this, wxSize(-1, -1)), 0);
    // Configure the fold margin
    compare_ctrl_in->SetMarginType(4, wxSTC_MARGIN_SYMBOL);
    compare_ctrl_in->SetMarginMask(4, wxSTC_MASK_FOLDERS);
    compare_ctrl_in->SetMarginSensitive(4, true);
    compare_ctrl_in->SetMarginWidth(4, 16);

    compare_ctrl_in->SetProperty(wxT("fold"), wxT("1"));
    compare_ctrl_in->MarkerDefine(wxSTC_MARKNUM_FOLDEROPEN, wxSTC_MARK_ARROWDOWN);
    compare_ctrl_in->MarkerDefine(wxSTC_MARKNUM_FOLDER, wxSTC_MARK_ARROW);
    compare_ctrl_in->MarkerDefine(wxSTC_MARKNUM_FOLDERSUB, wxSTC_MARK_BACKGROUND);
    compare_ctrl_in->MarkerDefine(wxSTC_MARKNUM_FOLDERTAIL, wxSTC_MARK_BACKGROUND);
    compare_ctrl_in->MarkerDefine(wxSTC_MARKNUM_FOLDEREND, wxSTC_MARK_ARROW);
    compare_ctrl_in->MarkerDefine(wxSTC_MARKNUM_FOLDEROPENMID, wxSTC_MARK_ARROWDOWN);
    compare_ctrl_in->MarkerDefine(wxSTC_MARKNUM_FOLDERMIDTAIL, wxSTC_MARK_BACKGROUND);
    // Configure the tracker margin
    compare_ctrl_in->SetMarginWidth(1, 0);

    // Configure the symbol margin
    compare_ctrl_in->SetMarginType(2, wxSTC_MARGIN_SYMBOL);
    compare_ctrl_in->SetMarginMask(2, ~(wxSTC_MASK_FOLDERS));
    compare_ctrl_in->SetMarginWidth(2, 0);
    compare_ctrl_in->SetMarginSensitive(2, true);

    // Configure the line numbers margin
    int compare_ctrl_in_PixelWidth = 4 + 5 * compare_ctrl_in->TextWidth(wxSTC_STYLE_LINENUMBER, wxT("9"));
    compare_ctrl_in->SetMarginType(0, wxSTC_MARGIN_NUMBER);
    compare_ctrl_in->SetMarginWidth(0, compare_ctrl_in_PixelWidth);

    // Configure the line symbol margin
    compare_ctrl_in->SetMarginType(3, wxSTC_MARGIN_FORE);
    compare_ctrl_in->SetMarginMask(3, 0);
    compare_ctrl_in->SetMarginWidth(3, 0);
    // Select the lexer
    compare_ctrl_in->SetLexer(wxSTC_LEX_NULL);
    // Set default font / styles
    compare_ctrl_in->StyleClearAll();
    compare_ctrl_in->SetWrapMode(0);
    compare_ctrl_in->SetIndentationGuides(0);
    compare_ctrl_in->SetKeyWords(0, wxT(""));
    compare_ctrl_in->SetKeyWords(1, wxT(""));
    compare_ctrl_in->SetKeyWords(2, wxT(""));
    compare_ctrl_in->SetKeyWords(3, wxT(""));
    compare_ctrl_in->SetKeyWords(4, wxT(""));

    dialog_sizer->Add(compare_ctrl_in, 1, wxALL | wxEXPAND, 5);

    compare_ctrl_out = new wxStyledTextCtrl(this, wxID_ANY, wxDefaultPosition, wxDLG_UNIT(this, wxSize(-1, -1)), 0);
    // Configure the fold margin
    compare_ctrl_out->SetMarginType(4, wxSTC_MARGIN_SYMBOL);
    compare_ctrl_out->SetMarginMask(4, wxSTC_MASK_FOLDERS);
    compare_ctrl_out->SetMarginSensitive(4, true);
    compare_ctrl_out->SetMarginWidth(4, 16);

    compare_ctrl_out->SetProperty(wxT("fold"), wxT("1"));
    compare_ctrl_out->MarkerDefine(wxSTC_MARKNUM_FOLDEROPEN, wxSTC_MARK_ARROWDOWN);
    compare_ctrl_out->MarkerDefine(wxSTC_MARKNUM_FOLDER, wxSTC_MARK_ARROW);
    compare_ctrl_out->MarkerDefine(wxSTC_MARKNUM_FOLDERSUB, wxSTC_MARK_BACKGROUND);
    compare_ctrl_out->MarkerDefine(wxSTC_MARKNUM_FOLDERTAIL, wxSTC_MARK_BACKGROUND);
    compare_ctrl_out->MarkerDefine(wxSTC_MARKNUM_FOLDEREND, wxSTC_MARK_ARROW);
    compare_ctrl_out->MarkerDefine(wxSTC_MARKNUM_FOLDEROPENMID, wxSTC_MARK_ARROWDOWN);
    compare_ctrl_out->MarkerDefine(wxSTC_MARKNUM_FOLDERMIDTAIL, wxSTC_MARK_BACKGROUND);
    // Configure the tracker margin
    compare_ctrl_out->SetMarginWidth(1, 0);

    // Configure the symbol margin
    compare_ctrl_out->SetMarginType(2, wxSTC_MARGIN_SYMBOL);
    compare_ctrl_out->SetMarginMask(2, ~(wxSTC_MASK_FOLDERS));
    compare_ctrl_out->SetMarginWidth(2, 0);
    compare_ctrl_out->SetMarginSensitive(2, true);

    // Configure the line numbers margin
    int compare_ctrl_out_PixelWidth = 4 + 5 * compare_ctrl_out->TextWidth(wxSTC_STYLE_LINENUMBER, wxT("9"));
    compare_ctrl_out->SetMarginType(0, wxSTC_MARGIN_NUMBER);
    compare_ctrl_out->SetMarginWidth(0, compare_ctrl_out_PixelWidth);

    // Configure the line symbol margin
    compare_ctrl_out->SetMarginType(3, wxSTC_MARGIN_FORE);
    compare_ctrl_out->SetMarginMask(3, 0);
    compare_ctrl_out->SetMarginWidth(3, 0);
    // Select the lexer
    compare_ctrl_out->SetLexer(wxSTC_LEX_NULL);
    // Set default font / styles
    compare_ctrl_out->StyleClearAll();
    compare_ctrl_out->SetWrapMode(0);
    compare_ctrl_out->SetIndentationGuides(0);
    compare_ctrl_out->SetKeyWords(0, wxT(""));
    compare_ctrl_out->SetKeyWords(1, wxT(""));
    compare_ctrl_out->SetKeyWords(2, wxT(""));
    compare_ctrl_out->SetKeyWords(3, wxT(""));
    compare_ctrl_out->SetKeyWords(4, wxT(""));

    dialog_sizer->Add(compare_ctrl_out, 1, wxALL | wxEXPAND, 5);

    dialog_sizer->Add(0, 0, 1, wxALL, 5);

    wxBoxSizer* button_sizer = new wxBoxSizer(wxHORIZONTAL);

    dialog_sizer->Add(button_sizer, 1, wxALL | wxEXPAND, 5);

    ok_btn = new wxButton(this, wxID_ANY, _("OK"), wxDefaultPosition, wxDLG_UNIT(this, wxSize(-1, -1)), 0);

    button_sizer->Add(ok_btn, 1, wxALL, 5);

    cancel_btn = new wxButton(this, wxID_ANY, _("Cancel"), wxDefaultPosition, wxDLG_UNIT(this, wxSize(-1, -1)), 0);

    button_sizer->Add(cancel_btn, 1, wxALL, 5);

//    SetName(wxT("compare_dialogue_base"));
    SetSize(wxDLG_UNIT(this, wxSize(800, 600)));
    
	if(GetSizer()) 
	{
		GetSizer()->Fit(this);
    }
    if(GetParent())
	{
		CentreOnParent(wxBOTH);
    } 
	else 
	{
		CentreOnScreen(wxBOTH);
    }
	this->ok_btn->Bind(wxEVT_COMMAND_BUTTON_CLICKED, &compare_dialog::ok_clicked, this);
	this->cancel_btn->Bind(wxEVT_COMMAND_BUTTON_CLICKED, &compare_dialog::cancel_clicked, this);
}

void compare_dialog::ok_clicked(wxCommandEvent& event)
{
	EndDialog(wxID_OK);
	event.Skip();
}

void compare_dialog::cancel_clicked(wxCommandEvent& event)
{
	EndDialog(wxID_CANCEL);
	event.Skip();
}

wxString compare_dialog::get_in_text() const
{
	return this->compare_ctrl_in->GetText();
}

wxString compare_dialog::get_out_text() const
{
	return this->compare_ctrl_out->GetText();
}

bool compare_dialog::save(const wxString& file_name) const
{
	return this->compare_ctrl_out->SaveFile(file_name);
}