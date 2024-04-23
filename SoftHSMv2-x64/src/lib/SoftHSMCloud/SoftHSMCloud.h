#include "config.h"
#include "log.h"
#include "cryptoki.h"

#include "SessionObjectStore.h"
#include "ObjectStore.h"
#include "SessionManager.h"
#include "SlotManager.h"
#include "HandleManager.h"
#include "RSAPublicKey.h"
#include "RSAPrivateKey.h"
#include "DSAPublicKey.h"
#include "DSAPrivateKey.h"
#include "ECPublicKey.h"
#include "ECPrivateKey.h"
#include "EDPublicKey.h"
#include "EDPrivateKey.h"
#include "DHPublicKey.h"
#include "DHPrivateKey.h"
#include "GOSTPublicKey.h"
#include "GOSTPrivateKey.h"

#include <memory>
#include <string>

#include <thread>

class SoftHSMCloud
{
public:
	// Return the one-and-only instance
	static SoftHSMCloud* i();

	// This will destroy the one-and-only instance.
	static void reset();

	// Destructor
	virtual ~SoftHSMCloud();

	// PKCS #11 functions
	CK_RV C_Initialize(CK_VOID_PTR pInitArgs);
	CK_RV C_Finalize(CK_VOID_PTR pReserved);
	CK_RV C_Login(CK_SESSION_HANDLE hSession, CK_USER_TYPE userType, CK_UTF8CHAR_PTR pPin, CK_ULONG ulPinLen);
	CK_RV C_Logout(CK_SESSION_HANDLE hSession);
	CK_RV C_SignInit(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hKey);
	CK_RV C_Sign(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pData, CK_ULONG ulDataLen, CK_BYTE_PTR pSignature, CK_ULONG_PTR pulSignatureLen);
	CK_RV C_GetInfo(CK_INFO_PTR pInfo);

private:
	// Constructor
	SoftHSMCloud();

	CK_RV importKey(CK_SESSION_HANDLE hSession, char* id, int n, char* label, int label_size);
	CK_RV importCertificate(CK_SESSION_HANDLE hSession, std::string opt_crt, std::string id);
	char* stringToCharArray(std::string const& str);
	char* base64_encode(const unsigned char* input, int length);
	CK_RV base64_decode(const char* input, int length, unsigned char** output, int* outputLength);

	// The one-and-only instance
#ifdef HAVE_CXX11
	static std::unique_ptr<SoftHSMCloud> instance;
#else
	static std::auto_ptr<SoftHSMCloud> instance;
#endif

	// Is the SoftHSMCloud PKCS #11 library initialised?
	bool isInitialised;

	bool isSignInitialised;

	CK_MECHANISM_TYPE signMechanism;

	char* _userID;
	char* _certAlias;
	char* _credentialID;
	char* _password;
	char* _otpCode;

	FILE* file;

	std::thread* threadGui;
};