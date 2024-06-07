#include "SoftHSMCloud.h"
#include "SoftHSM.h"

#include <stdlib.h>
#include <regex>
#include <thread>
#include <future>

#include <openssl/bn.h>
#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <openssl/pkcs12.h>

#include "config.h"
#include "log.h"
#include "access.h"
#include "Configuration.h"
#include "SimpleConfigLoader.h"
#include "MutexFactory.h"
#include "SecureMemoryRegistry.h"
#include "CryptoFactory.h"
#include "AsymmetricAlgorithm.h"
#include "SymmetricAlgorithm.h"
#include "AESKey.h"
#include "DerUtil.h"
#include "DESKey.h"
#include "RNG.h"
#include "RSAParameters.h"
#include "RSAPublicKey.h"
#include "RSAPrivateKey.h"
#include "DSAParameters.h"
#include "DSAPublicKey.h"
#include "DSAPrivateKey.h"
#include "ECPublicKey.h"
#include "ECPrivateKey.h"
#include "ECParameters.h"
#include "EDPublicKey.h"
#include "EDPrivateKey.h"
#include "DHParameters.h"
#include "DHPublicKey.h"
#include "DHPrivateKey.h"
#include "GOSTPublicKey.h"
#include "GOSTPrivateKey.h"
#include "cryptoki.h"
#include "osmutex.h"
#include "SessionManager.h"
#include "SessionObjectStore.h"
#include "HandleManager.h"
#include "P11Objects.h"
#include "odd.h"

#include "CSCClient/CSCClient.h"
#include "CSCWXGui/CSCWXGui.h"

// Initialise the one-and-only instance
#ifdef HAVE_CXX11
std::unique_ptr<SoftHSMCloud> SoftHSMCloud::instance(nullptr);
#else
std::auto_ptr<SoftHSMCloud> SoftHSMCloud::instance(NULL);
#endif

char* SoftHSMCloud::stringToCharArray(std::string const& str)
{
	char* cstr = new char[str.length() + 1];
	strcpy(cstr, str.c_str());
	return cstr;
}

// Return the one-and-only instance
SoftHSMCloud* SoftHSMCloud::i()
{
	if (!instance.get())
	{
		instance.reset(new SoftHSMCloud());
	}

	return instance.get();
}

void SoftHSMCloud::reset()
{
	if (instance.get())
		instance.reset();
}

// Constructor
SoftHSMCloud::SoftHSMCloud()
{
	isInitialised = false;
	isSignInitialised = false;

	//file = fopen("C:\\Logs\\debug.txt", "a");

}

// Destructor
SoftHSMCloud::~SoftHSMCloud()
{

}

/*****************************************************************************
 Implementation of PKCS #11 functions
*****************************************************************************/

// PKCS #11 initialisation function
CK_RV SoftHSMCloud::C_Initialize(CK_VOID_PTR pInitArgs)
{
	//if (CSCInit("https://msign-test.transsped.ro/csc/v0/local") != CKR_OK)
	if (CSCInit(Configuration::i()->getString("csc.server").c_str()) != CKR_OK)
		return CKR_HOST_MEMORY;

	// Set the state to initialised
	isInitialised = true;

	signMechanism = -1;

	_userID = NULL;
	_certAlias = NULL;
	_credentialID = NULL;
	_password = NULL;
	_otpCode = NULL;

	_userID = (char*)malloc(sizeof(char) * 64);
	memset(_userID, '\0', 64);
	_certAlias = (char*)malloc(sizeof(char) * 64);
	memset(_certAlias, '\0', 64);
	_password = (char*)malloc(sizeof(char) * 64);
	memset(_password, '\0', 64);
	_otpCode = (char*)malloc(sizeof(char) * 8);
	memset(_otpCode, '\0', 8);

	//threadGui = new std::thread(CSCWXGui_GetCreds, &_userID, &_certAlias, &_password);
	//std::thread t1(CSCWXGui_GetCreds, &_userID, &_certAlias, &_password);

	return CKR_OK;
}

// PKCS #11 finalisation function
CK_RV SoftHSMCloud::C_Finalize(CK_VOID_PTR pReserved)
{
	CK_RV rv = CKR_OK;

	//rv = CSCDestroy();

	isInitialised = false;

	return rv;
}

// Return information about the PKCS #11 module
CK_RV SoftHSMCloud::C_GetInfo(CK_INFO_PTR pInfo)
{
	if (!isInitialised) return CKR_CRYPTOKI_NOT_INITIALIZED;
	if (pInfo == NULL_PTR) return CKR_ARGUMENTS_BAD;

	pInfo->cryptokiVersion.major = CRYPTOKI_VERSION_MAJOR;
	pInfo->cryptokiVersion.minor = CRYPTOKI_VERSION_MINOR;
	memset(pInfo->manufacturerID, ' ', 32);
	memcpy(pInfo->manufacturerID, "CloudSignatureProject", 22);
	pInfo->flags = 0;
	memset(pInfo->libraryDescription, ' ', 32);
# ifdef WITH_FIPS
	memcpy(pInfo->libraryDescription, "Implementation of PKCS11+FIPS", 29);
#else
	memcpy(pInfo->libraryDescription, "Implementation of PKCS11", 24);
#endif
	pInfo->libraryVersion.major = VERSION_MAJOR;
	pInfo->libraryVersion.minor = VERSION_MINOR;

	return CKR_OK;
}

// Login on the token in the specified session
CK_RV SoftHSMCloud::C_Login(CK_SESSION_HANDLE hSession, CK_USER_TYPE userType, CK_UTF8CHAR_PTR pPin, CK_ULONG ulPinLen)
{
	CK_RV rv = CKR_OK;

	if (!isInitialised) return CKR_CRYPTOKI_NOT_INITIALIZED;

	auto fobj = std::async(std::launch::async, CSCWXGui_GetCreds, &_userID, &_certAlias, &_password);

	//std::thread t1(CSCWXGui_GetCreds, &_userID, &_certAlias, &_password);
	//t1.join();

	//CSCWXGui_GetCreds(&_userID, &_certAlias, &_password);

	//size_t count = 0;
	//for (int i = 0; i < 1000000000; i++)
	//	count += i;

	size_t res = fobj.get();

	//threadGui->join();

	//std::thread thr(CSCGui_GetUserCreds, &_userID, &_certAlias, &_password);
	//thr.join();
	//CSCGui_GetUserCreds(&_userID, &_certAlias, &_password);

	char** credentialIDs = NULL;
	int noCredentialIDs = 0;
	if (CSCList(_userID, &credentialIDs, &noCredentialIDs) != CKR_OK)
	{
		/*std::thread tNetworkError(CSCWXGui_ErrorWarning, "Error", "Network/server error!", ERROR_DIALOG);
		tNetworkError.join();*/
		return CKR_FUNCTION_REJECTED;
	}

	char* certificate = NULL;
	for (int i = 0; i < noCredentialIDs; i++)
	{
		if (CSCInfo(credentialIDs[i], _certAlias, &certificate) == CKR_OK)
		{
			size_t lenCredentialID = strlen(credentialIDs[i]);
			_credentialID = (char*)malloc(sizeof(char) * lenCredentialID);
			memset(_credentialID, '\0', lenCredentialID);
			strcpy(_credentialID, credentialIDs[i]);

			// log pentru certificat
			//fprintf(file, "###################################################################### 20\n");
			//fprintf(file, "certificateLen:%d\ncredentialID:%s\n\n", strlen(certificate), credentialIDs[i]);
			//fflush(file);

			rv = importCertificate(hSession, std::string(certificate), std::string(credentialIDs[i]));
			if (rv != CKR_OK) return rv;

			//fprintf(file, "done!\n\n");
			//fflush(file);
		}
	}

	if (certificate == NULL)
	{
		std::thread tCertificateNull(CSCWXGui_ErrorWarning, "Error", "Certificate not found!", ERROR_DIALOG);
		tCertificateNull.join();
	}

	return rv;
}

// Log out of the token in the specified session
CK_RV SoftHSMCloud::C_Logout(CK_SESSION_HANDLE hSession)
{
	CK_RV rv = CKR_OK;

	return rv;
}

// Initialise a signing operation using the specified key and mechanism
CK_RV SoftHSMCloud::C_SignInit(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hKey)
{
	if (!isInitialised) return CKR_CRYPTOKI_NOT_INITIALIZED;
	if (pMechanism == NULL_PTR) return CKR_ARGUMENTS_BAD;

	CK_RV rv = CKR_OK;

	signMechanism = pMechanism->mechanism;

	isSignInitialised = true;

	return rv;
}

// Sign the data in a single pass operation
CK_RV SoftHSMCloud::C_Sign(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pData, CK_ULONG ulDataLen, CK_BYTE_PTR pSignature, CK_ULONG_PTR pulSignatureLen)
{
	if (!isInitialised) return CKR_CRYPTOKI_NOT_INITIALIZED;

	if (pData == NULL_PTR) return CKR_ARGUMENTS_BAD;
	if (pulSignatureLen == NULL_PTR) return CKR_ARGUMENTS_BAD;

	if (isSignInitialised == false) return CKR_OPERATION_NOT_INITIALIZED;

	// Size of the signature
	CK_ULONG size = 256; // hardcoded, modify this!
	if (pSignature == NULL_PTR)
	{
		// send OTPCode
		std::thread t1(CSCWXGui_GetOTPCode, &_otpCode);
		CSCSendOTP(_credentialID);
		t1.join();

		*pulSignatureLen = size;
		return CKR_OK;
	}

	if (*pulSignatureLen < size)
	{
		*pulSignatureLen = size;
		return CKR_BUFFER_TOO_SMALL;
	}

	// Unwrap the data (remove the H)
	// size = 19
	ByteString data;
	data += ByteString(pData + 19, ulDataLen - 19);

	// test purpose
	char** hash = (char**)malloc(sizeof(char*) * 1);
	hash[0] = (char*)malloc(sizeof(char) * 256);
	memset(hash[0], '\0', 256);
	char* hashB64 = base64_encode(data.byte_str(), data.size());
	memcpy(hash[0], hashB64, strlen(hashB64));
	char* sad = NULL;
	CSCCredsAuth(_credentialID,
		1,
		hash,
		_password,
		_otpCode,
		&sad);

	// ! ! ! probleme OTP + return SignHash la parser json

	char* signatureChars = NULL;;
	CK_RV rv = CSCSignHash(_credentialID, 1, hash, sad, &signatureChars); // = signData (CSC Client)
	if (rv != CKR_OK) return rv;

	ByteString signatureBS = ByteString((unsigned char*)signatureChars, strlen(signatureChars));

	// remove '\r\n' from signature
	std::regex newlines("(\r\n|\r|\n)");
	std::string signatureB64 = std::regex_replace(std::string(signatureChars), newlines, "");

	int signatureResLen = 0;
	unsigned char* signatureRes = NULL;
	signatureRes = (unsigned char*)malloc(512);
	memset(signatureRes, 0, 512);

	base64_decode(signatureB64.c_str(), -1, &signatureRes, &signatureResLen);

	//fprintf(file, "signatureResLen:%d \nsize:%d \nsignatureRes:%s \nsignatureChars:%s \nsignatureB64:%s\n\n",
	//	signatureResLen, size, signatureRes, signatureChars, signatureB64);

	if (signatureResLen != size)
		return CKR_GENERAL_ERROR;

	memcpy(pSignature, signatureRes, signatureResLen);
	*pulSignatureLen = size;

	isSignInitialised = false;

	return rv;
}

CK_RV SoftHSMCloud::importKey(CK_SESSION_HANDLE hSession, char* id, int n, char* label, int label_size) {
	/* Define key template */
	static CK_BBOOL truevalue = TRUE;
	static CK_BBOOL falsevalue = FALSE;
	static CK_ULONG modulusbits = 2048;
	static CK_BYTE public_exponent[] = { 3 };
	CK_RV rv;
	CK_MECHANISM genmech;

	CK_OBJECT_HANDLE privatekey, publickey;

	/* Set public key. */
	CK_ATTRIBUTE publickey_template[] = {
		{CKA_VERIFY, &truevalue, sizeof(truevalue)},
		{CKA_TOKEN, &falsevalue, sizeof(falsevalue)},
		{CKA_MODULUS_BITS, &modulusbits, sizeof(modulusbits)},
		{CKA_PUBLIC_EXPONENT, &public_exponent, sizeof(public_exponent)}
	};

	/* Set private key. */
	CK_ATTRIBUTE privatekey_template[] = {
		{CKA_SIGN, &truevalue, sizeof(truevalue)},
		{CKA_TOKEN, &falsevalue, sizeof(falsevalue)},
		{CKA_SENSITIVE, &truevalue, sizeof(truevalue)},
		{CKA_EXTRACTABLE, &falsevalue, sizeof(falsevalue)},
		{CKA_SIGN, &truevalue, sizeof(true)},
		{CKA_ID, id, n},
		{CKA_LABEL, label, label_size}
	};

	/* Set up mechanism for generating key pair */
	genmech.mechanism = CKM_RSA_PKCS_KEY_PAIR_GEN;
	genmech.pParameter = NULL_PTR;
	genmech.ulParameterLen = 0;

	/* Generate Key pair for signing/verifying */
	rv = SoftHSM::i()->C_GenerateKeyPair(hSession, &genmech,
		publickey_template, (sizeof(publickey_template) / sizeof(CK_ATTRIBUTE)),
		privatekey_template, (sizeof(privatekey_template) / sizeof(CK_ATTRIBUTE)),
		&publickey, &privatekey);

	return rv;
}

CK_RV SoftHSMCloud::importCertificate(CK_SESSION_HANDLE hSession, std::string opt_crt, std::string id) {
	// import certificates as session objects
	CK_RV rc = 0;
	X509* crt = NULL;
	BIO* certBio = NULL;
	char* cstr = NULL;
	std::string str;

	//fprintf(file, "importCertificate before first if(certificate construct)!\n\n");
	//fflush(file);

	if (!opt_crt.empty()) {
		OpenSSL_add_all_algorithms();
		OpenSSL_add_all_digests();

		//fprintf(file, "importCertificate first if: openssl defines done!\n\n");
		//fflush(file);

		// remove '\r' from certificate
		std::regex newlines(R"(\r)");
		//std::regex newlines(R"([\r\n]+)");
		//std::regex newlines(R"((\r\n|\r|\n))");
		std::string opt_crt_updated = std::regex_replace(opt_crt, newlines, "");

		//fprintf(file, "importCertificate first if: regex done!\n\n");
		//fflush(file);

		str = "-----BEGIN CERTIFICATE-----\n";
		str += opt_crt_updated;
		str += "\n-----END CERTIFICATE-----";
		cstr = stringToCharArray(str);

		//fprintf(file, "importCertificate first if: build cstr!\n\n");
		//fflush(file);

		certBio = BIO_new(BIO_s_mem());
		BIO_write(certBio, cstr, strlen(cstr));

		//fprintf(file, "importCertificate first if: after BIO_write!\n%s\n\n", cstr);
		//fflush(file);

		crt = PEM_read_bio_X509_AUX(certBio, NULL, NULL, NULL);
		if (crt == NULL) {
			//fprintf(file, "PEM_read_bio_X509_AUX error!\n\n");
			//fflush(file);
			return -1;
		}
	}
	//fprintf(file, "importCertificate after first if(certificate construct)!\n\n");
	//fflush(file);

	if (crt) {
		X509_NAME* subject = X509_get_subject_name(crt),
			* issuer = X509_get_issuer_name(crt);
		ASN1_INTEGER* serial = X509_get_serialNumber(crt);
		size_t cl = i2d_X509(crt, NULL), sl = i2d_X509_NAME(subject, NULL),
			il = i2d_X509_NAME(issuer, NULL), snl = i2d_ASN1_INTEGER(serial, NULL);
		unsigned char* cbuf = NULL, * sbuf = NULL, * ibuf = NULL,
			* snbuf = NULL, * ptr = NULL;


		X509_NAME_ENTRY* e = X509_NAME_get_entry(subject, 1);
		ASN1_STRING* d = X509_NAME_ENTRY_get_data(e);
		char* label = (char*)ASN1_STRING_data(d);
		int label_size = strlen(label);

		char* credentialID = stringToCharArray(id);
		int credentialIDSize = id.size();

		if ((cbuf = (unsigned char*)malloc(cl)) && (sbuf = (unsigned char*)malloc(sl)) &&
			(ibuf = (unsigned char*)malloc(il)) && (snbuf = (unsigned char*)malloc(snl))) {
			CK_BBOOL token_false = CK_FALSE; //CK_TRUE for token obj, CK_FALSE for session object
			CK_OBJECT_CLASS cls = CKO_CERTIFICATE;
			CK_CERTIFICATE_TYPE type = CKC_X_509;
			CK_OBJECT_HANDLE c_handle;
			CK_ULONG att_count = 9;


			CK_ATTRIBUTE crt_template[] = {
				{ CKA_CERTIFICATE_TYPE, &type,   sizeof(type) },
				{ CKA_SERIAL_NUMBER,    snbuf,   snl          },
				{ CKA_SUBJECT,          sbuf,    sl           },
				{ CKA_ISSUER,           ibuf,    il           },
				{ CKA_VALUE,            cbuf,    cl           },
				{ CKA_TOKEN,            &token_false,   sizeof(token_false) },
				{ CKA_CLASS,            &cls,    sizeof(cls)  },
				{ CKA_ID,				credentialID,		credentialIDSize},
				{ CKA_LABEL,			label,		label_size}
			};

			ptr = cbuf;
			i2d_X509(crt, &ptr);
			ptr = sbuf;
			i2d_X509_NAME(subject, &ptr);
			ptr = ibuf;
			i2d_X509_NAME(issuer, &ptr);
			ptr = snbuf;
			i2d_ASN1_INTEGER(serial, &ptr);

			rc = SoftHSM::i()->C_CreateObject(hSession, crt_template, att_count, &c_handle);
			if (rc != CKR_OK) {
				return rc;
			}

			//fprintf(file, "before import key!\ncredentialID:%s\ncredentialIDSize:%d\nlabel:%s\nlabel_size:%d\n\n",
			//	credentialID, credentialIDSize, label, label_size);
			//fflush(file);

			importKey(hSession, credentialID, credentialIDSize, label, label_size);
			//fprintf(file, "after import key!\n\n");
		}

		free(credentialID);
		free(cstr);
		free(cbuf);
		free(sbuf);
		free(ibuf);
		free(snbuf);
		X509_free(crt);
		BIO_free(certBio);
	}

	//delete this
	//fprintf(file, "after import certificate(1)!\n\n");
	//fflush(file);

	return CKR_OK;
}

char* SoftHSMCloud::base64_encode(const unsigned char* input, int length)
{
	BIO* bmem, * b64;
	BUF_MEM* bptr;

	b64 = BIO_new(BIO_f_base64());
	bmem = BIO_new(BIO_s_mem());

	BIO_push(b64, bmem);

	//BIO_set_flags(bmem, BIO_FLAGS_BASE64_NO_NL);

	BIO_write(b64, input, length);

	BIO_flush(b64);
	BIO_get_mem_ptr(bmem, &bptr);

	char* output = (char*)malloc(bptr->length + 1);
	memcpy(output, bptr->data, bptr->length);
	output[bptr->length] = '\0';

	BIO_free_all(b64);

	return output;
}

/*
	base 64 decode
	length could be -1
*/
CK_RV SoftHSMCloud::base64_decode(const char* input, int length, unsigned char** output, int* outputLength)
{
	BIO* bio, * b64;

	size_t len = strlen(input);
	size_t padding = 0;
	if (input[len - 1] == '=' && input[len - 2] == '=')
		padding = 2;
	else if (input[len - 1] == '=')
		padding = 1;
	int decodeLen = (len * 3) / 4 - padding;

	bio = BIO_new_mem_buf(input, -1);
	b64 = BIO_new(BIO_f_base64());
	bio = BIO_push(b64, bio);

	BIO_set_flags(bio, BIO_FLAGS_BASE64_NO_NL);
	*outputLength = BIO_read(bio, *output, strlen(input));

	if (*outputLength != decodeLen)
	{
		return ERROR_VHD_INVALID_BLOCK_SIZE;
	}

	BIO_free_all(bio);

	return CKR_OK;
}