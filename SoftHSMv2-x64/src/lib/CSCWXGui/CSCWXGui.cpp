#include <wx/wx.h>
#include "CSCWXGui.h"

class LoginDialog : public wxDialog {
public:
	wxTextCtrl* usernameCtrl;
	wxTextCtrl* certaliasCtrl;
	wxTextCtrl* passwordCtrl;

	LoginDialog(const wxString& title)
		: wxDialog(NULL, -1, title, wxDefaultPosition, wxSize(400, 250)) {
		wxPanel* panel = new wxPanel(this, -1);

		wxFont font = panel->GetFont();
		font.SetPointSize(font.GetPointSize() + 10);
		panel->SetFont(font);

		wxBoxSizer* vbox = new wxBoxSizer(wxVERTICAL);
		wxBoxSizer* hbox1 = new wxBoxSizer(wxHORIZONTAL);
		wxBoxSizer* hbox2 = new wxBoxSizer(wxHORIZONTAL);
		wxBoxSizer* hbox3 = new wxBoxSizer(wxHORIZONTAL);
		wxBoxSizer* hbox4 = new wxBoxSizer(wxHORIZONTAL);

		wxStaticText* st1 = new wxStaticText(panel, wxID_ANY, wxT("User ID "));
		usernameCtrl = new wxTextCtrl(panel, wxID_ANY);

		hbox1->Add(st1, 0, wxRIGHT, 8);
		hbox1->Add(usernameCtrl, 1);

		wxStaticText* st2 = new wxStaticText(panel, wxID_ANY, wxT("Certificate alias"));
		certaliasCtrl = new wxTextCtrl(panel, wxID_ANY);

		hbox2->Add(st2, 0, wxRIGHT, 8);
		hbox2->Add(certaliasCtrl, 1);

		wxStaticText* st3 = new wxStaticText(panel, wxID_ANY, wxT("Password"));
		passwordCtrl = new wxTextCtrl(panel, wxID_ANY, wxString(""), wxPoint(-1, -1),
			wxSize(-1, -1), wxTE_PASSWORD);

		hbox3->Add(st3, 0, wxRIGHT, 8);
		hbox3->Add(passwordCtrl, 1);

		wxButton* btn1 = new wxButton(panel, wxID_OK, wxT("Ok"), wxDefaultPosition, wxSize(100, 40));
		wxButton* btn2 = new wxButton(panel, wxID_CANCEL, wxT("Cancel"), wxDefaultPosition,
			wxSize(100, 40));

		hbox4->Add(btn1, 0);
		hbox4->Add(btn2, 0, wxLEFT, 5);

		vbox->Add(hbox1, 0, wxEXPAND | wxLEFT | wxRIGHT | wxTOP, 10);
		vbox->Add(hbox2, 0, wxEXPAND | wxLEFT | wxRIGHT | wxTOP, 10);
		vbox->Add(hbox3, 0, wxEXPAND | wxLEFT | wxRIGHT | wxTOP, 10);
		vbox->Add(hbox4, 0, wxALIGN_CENTER | wxTOP | wxBOTTOM, 10);

		panel->SetSizer(vbox);

		Centre();
	}
};

class OTPCodeDialog : public wxDialog {
public:
	wxTextCtrl* otpCodeWXTC;

	OTPCodeDialog(const wxString& title)
		: wxDialog(NULL, -1, title, wxDefaultPosition, wxSize(400, 150)) {
		wxPanel* panel = new wxPanel(this, -1);

		wxFont font = panel->GetFont();
		font.SetPointSize(font.GetPointSize() + 10);
		panel->SetFont(font);

		wxBoxSizer* vbox = new wxBoxSizer(wxVERTICAL);
		wxBoxSizer* hbox1 = new wxBoxSizer(wxHORIZONTAL);
		wxBoxSizer* hbox2 = new wxBoxSizer(wxHORIZONTAL);

		wxStaticText* st1 = new wxStaticText(panel, wxID_ANY, wxT("OTP Code"));
		otpCodeWXTC = new wxTextCtrl(panel, wxID_ANY);

		hbox1->Add(st1, 0, wxRIGHT, 8);
		hbox1->Add(otpCodeWXTC, 1);

		wxButton* btn1 = new wxButton(panel, wxID_OK, wxT("Ok"), wxDefaultPosition, wxSize(100, 40));
		wxButton* btn2 = new wxButton(panel, wxID_CANCEL, wxT("Cancel"), wxDefaultPosition,
			wxSize(100, 40));

		hbox2->Add(btn1, 0);
		hbox2->Add(btn2, 0, wxLEFT, 5);

		vbox->Add(hbox1, 0, wxEXPAND | wxLEFT | wxRIGHT | wxTOP, 10);
		vbox->Add(hbox2, 0, wxALIGN_CENTER | wxTOP | wxBOTTOM, 10);

		panel->SetSizer(vbox);

		Centre();
	}
};

class ErrorWarningDialog : public wxDialog {
public:
	ErrorWarningDialog(const wxString& title, const wxString& message, int dialogType)
		: wxDialog(NULL, -1, title, wxDefaultPosition, wxSize(500, 300)) {
		wxPanel* panel = new wxPanel(this, -1);

		wxFont font = panel->GetFont();
		font.SetPointSize(font.GetPointSize() + 8);
		panel->SetFont(font);

		wxBoxSizer* vbox = new wxBoxSizer(wxVERTICAL);
		wxBoxSizer* hbox1 = new wxBoxSizer(wxHORIZONTAL);
		wxBoxSizer* hbox2 = new wxBoxSizer(wxHORIZONTAL);

		wxStaticText* st1 = new wxStaticText(panel, wxID_ANY, message);
		st1->Wrap(380);
		if (dialogType == ERROR_DIALOG)
			st1->SetForegroundColour(wxColor(255, 0, 0));
		else if (dialogType == WARNING_DIALOG)
			st1->SetForegroundColour(wxColor(252, 186, 3));

		hbox1->Add(st1, 0, wxRIGHT | wxLEFT, 8);

		wxButton* btn1 = new wxButton(panel, wxID_OK, wxT("Ok"), wxDefaultPosition, wxSize(100, 40));

		hbox2->Add(btn1, 0);

		vbox->Add(hbox1, 0, wxALIGN_CENTER | wxLEFT | wxRIGHT | wxTOP, 10);
		vbox->Add(hbox2, 0, wxALIGN_CENTER | wxTOP | wxBOTTOM, 10);

		panel->SetSizer(vbox);

		Centre();
	}
};

class MyApp : public wxApp {
public:
	virtual bool OnInit() {

		return false;
	}

};

wxIMPLEMENT_APP_NO_MAIN(MyApp);
wxDECLARE_APP(MyApp);

size_t CSCWXGui_GetCreds(char** userID, char** certAlias, char** password)
{
	//*userID = (char*)malloc(sizeof(char) * 64);
	//memset(*userID, '\0', 64);
	//*certAlias = (char*)malloc(sizeof(char) * 64);
	//memset(*certAlias, '\0', 64);
	//*password = (char*)malloc(sizeof(char) * 64);
	//memset(*password, '\0', 64);

	wxApp::SetInstance(new MyApp());
	wxEntryStart(0, nullptr);
	wxTheApp->CallOnInit();

	LoginDialog* dialog = new LoginDialog(wxT("Login - user credentials"));
	if (dialog->ShowModal() == wxID_OK) {
		//wxString usernameWXStr = dialog->usernameCtrl->GetValue();
		//wxString certaliasWXStr = dialog->certaliasCtrl->GetValue();
		//wxString passwordWXStr = dialog->passwordCtrl->GetValue();

		//*userID = _strdup(usernameWXStr.utf8_str().data());
		//*certAlias = _strdup(certaliasWXStr.utf8_str().data());
		//*password = _strdup(passwordWXStr.utf8_str().data());

		*userID = _strdup(dialog->usernameCtrl->GetValue().utf8_str().data());
		*certAlias = _strdup(dialog->certaliasCtrl->GetValue().utf8_str().data());
		*password = _strdup(dialog->passwordCtrl->GetValue().utf8_str().data());
	}
	dialog->Destroy();

	wxTheApp->OnRun();

	wxTheApp->OnExit();
	wxEntryCleanup();

	return 0;
}

size_t CSCWXGui_GetOTPCode(char** code)
{
	*code = (char*)malloc(sizeof(char) * 8);
	memset(*code, '\0', 8);

	wxApp::SetInstance(new MyApp());
	wxEntryStart(0, nullptr);
	wxTheApp->CallOnInit();

	OTPCodeDialog* dialog = new OTPCodeDialog(wxT("OTP Code"));
	if (dialog->ShowModal() == wxID_OK) {
		wxString otpCodeWXS = dialog->otpCodeWXTC->GetValue();

		*code = _strdup(otpCodeWXS.utf8_str().data());
	}
	dialog->Destroy();

	wxTheApp->OnRun();

	wxTheApp->OnExit();
	wxEntryCleanup();

	return 0;
}

size_t CSCWXGui_ErrorWarning(const char* title, const char* message, int type)
{
	wxApp::SetInstance(new MyApp());
	wxEntryStart(0, nullptr);
	wxTheApp->CallOnInit();

	ErrorWarningDialog* dialog = new ErrorWarningDialog(wxString(title), wxString(message), type);
	if (dialog->ShowModal() == wxID_OK) {

	}
	dialog->Destroy();

	wxTheApp->OnRun();

	wxTheApp->OnExit();
	wxEntryCleanup();

	return 0;
}