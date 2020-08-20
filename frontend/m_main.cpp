#include "main_frame.h"
#include "constants.h"


m_main::m_main() : wxFrame(nullptr, wxID_ANY, constants::main_frame::MAIN_TITLE, wxPoint(360, 240), wxSize(1024, 768))
{
	auto * sizer = new wxBoxSizer(wxVERTICAL);
	this->SetSizer(sizer);
	
	this->tabs_container = new wxAuiNotebook(this, constants::main_frame::TAB_CONTAINER_ID, wxDefaultPosition, wxDLG_UNIT(this, wxSize(250, 250)), wxAUI_NB_TAB_FIXED_WIDTH);
	
	this->envelope_panel = new m_envelope_panel(this, constants::envelope_panel::ENVELOPE_PANEL_ID);
	this->tabs_container->AddPage(this->envelope_panel, constants::envelope_panel::ENVELOPE_PANEL_NAME, true);
	
	
}

m_main::~m_main()
{
}

