#ifndef M_APP_HPP
#define M_APP_HPP

#include "wx/wx.h"

#include "main_frame.h"

struct app : public wxApp
{
	app();
	
	virtual bool OnInit();
	virtual int OnExit();
	
private:
	main_frame * main_frame_ = nullptr;
};

#endif // M_APP_HPP
