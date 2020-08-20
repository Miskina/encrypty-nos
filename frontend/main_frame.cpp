#include "main_frame.h"
#include "constants.h"


main_frame::main_frame() : wxFrame(nullptr, wxID_ANY, constants::mn_frm::MAIN_TITLE, wxPoint(360, 240), wxSize(1024, 768))
{
	auto * sizer = new wxBoxSizer(wxVERTICAL);
	this->SetSizer(sizer);
	
	this->tabs_container = new wxAuiNotebook(this, wxID_ANY, wxDefaultPosition, wxDLG_UNIT(this, wxSize(250, 250)), wxAUI_NB_TAB_FIXED_WIDTH|wxBK_DEFAULT);
	this->tabs_container->SetName(wxT("Kripto tabs"));
    sizer->Add(this->tabs_container, 1, wxALL|wxEXPAND, 5);
	
	this->env_pnl = new wxPanel(this->tabs_container, wxID_ANY, wxDefaultPosition, wxDLG_UNIT(this->tabs_container, wxSize(-1, -1)), wxTAB_TRAVERSAL | wxBORDER_SUNKEN);
	wxBoxSizer * env_pnl_sizer = new wxBoxSizer(wxVERTICAL);
	this->env_pnl->SetSizer(env_pnl_sizer);
	this->tabs_container->AddPage(this->env_pnl, constants::env_pnl::ENVELOPE_PANEL_NAME, true);
	
	this->env_win = new envelope_window(this->env_pnl, wxID_ANY);
	env_pnl_sizer->Add(this->env_win, 1, wxALL|wxEXPAND, 5);
	
	this->sign_pnl = new wxPanel(this->tabs_container, wxID_ANY, wxDefaultPosition, wxDLG_UNIT(this->tabs_container, wxSize(-1, -1)), wxTAB_TRAVERSAL|wxBORDER_SUNKEN);
	this->tabs_container->AddPage(sign_pnl, _("Signature"), false);
    
    wxBoxSizer * signature_panel_sizer = new wxBoxSizer(wxVERTICAL);
    this->sign_pnl->SetSizer(signature_panel_sizer);
    
	this->sign_win = new signature_window(this->sign_pnl, wxID_ANY);
	signature_panel_sizer->Add(this->sign_win, 1, wxALL | wxEXPAND, 5);
	
	seal_pnl = new wxPanel(tabs_container, wxID_ANY, wxDefaultPosition, wxDLG_UNIT(tabs_container, wxSize(-1,-1)), wxTAB_TRAVERSAL|wxBORDER_SUNKEN);
    tabs_container->AddPage(seal_pnl, _("Digital Seal"), false);
    
    wxBoxSizer* seal_panel_sizer = new wxBoxSizer(wxVERTICAL);
    seal_pnl->SetSizer(seal_panel_sizer);
    
    seal_win = new seal_window(seal_pnl, wxID_ANY);
    
    seal_panel_sizer->Add(seal_win, 1, wxALL|wxEXPAND, 5);
    
}

