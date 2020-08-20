#ifndef M_MAIN_HPP
#define M_MAIN_HPP

#include "wx/wx.h"
#include "wx/aui/auibook.h"

#include "envelope_window.h"
#include "signature_window.h"
#include "seal_window.h"

struct main_frame : public wxFrame
{
	main_frame();
	
private:
	wxAuiNotebook * tabs_container;
	
	wxPanel * env_pnl;
	envelope_window * env_win;
	
	wxPanel * sign_pnl;
	signature_window * sign_win;
	
	wxPanel * seal_pnl;
	seal_window * seal_win;
	
};

#endif // M_MAIN_HPP
