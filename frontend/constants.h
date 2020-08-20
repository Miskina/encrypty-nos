#ifndef FRONTEND_CONSTANTS
#define FRONTEND_CONSTANTS

#include "wx/wx.h"


namespace constants
{
	static const wxString APP_NAME = "Kripto NOS";
	
	namespace mn_frm
	{
		static const wxString& MAIN_TITLE = APP_NAME;
		
		static const wxWindowID TAB_CONTAINER_ID = 10000;
	};
	
	namespace env_pnl
	{
		static const wxWindowID ENVELOPE_PANEL_ID = 10100;
		static const wxString ENVELOPE_PANEL_NAME = "Envelope"; 
		
		static const wxWindowID SYMM_NOS_BTN_ID = 10101;
		static const wxWindowID RAND_SYMM_KEY_BTN_ID = 10102;
		static const wxWindowID RAND_IV_BTN_ID = 10103;
		static const wxWindowID GEN_E_KEY_BTN_ID = 10104;
		static const wxWindowID ASYM_NOS_BTN_ID = 10105;
		static const wxWindowID SEAL_IN_BTN_ID = 10106;
		static const wxWindowID SEAL_OUT_BTN_ID = 10107;
		static const wxWindowID OPEN_IN_BTN_ID = 10108;
		static const wxWindowID OPEN_OUT_BTN_ID = 10109;
		static const wxWindowID SEAL_BTN_ID = 10110;
		static const wxWindowID OPEN_BTN_ID = 10111;
		static const wxWindowID SYMM_ALOG_RB_ID = 10112;
		static const wxWindowID N_CTRL_ID = 10113;
		static const wxWindowID E_CTRL_ID = 10114;
		static const wxWindowID D_CTRL_ID = 10115;
	};
	
	
	
	
	namespace signature_panel
	{
		
	};
};


#endif