#pragma once

typedef unsigned long CSC_RV;

#define CSC_SUCCESS (0UL)
#define CSC_FAILED (1001UL)
#define CSC_MALLOC_ERROR (1002UL)
#define CSC_JSON_PARSER_ERROR (1011UL)
#define CSC_JSON_CREATE_ERROR (1012UL)
#define CSC_CURL_PERFORM_ERROR (1021UL)
#define CSC_CURL_INIT_ERROR (1021UL)

#define CSC_CERTIFICATE_ALIAS_MATCH_ERROR (2000UL)

#pragma region Test
// just an example for test only [delete me]
CSC_RV exampleCURL();

// just for test [delete me]
CSC_RV mainTEST();
#pragma endregion

// set base URL for CSC Client
CSC_RV CSCInit(const char* baseURL);

// delete instance
CSC_RV CSCDestroy();

// get userID and return credential id list in credentialIDs parameter
CSC_RV CSCList(const char* userID, char*** credentialIDs, int* noIDs);

CSC_RV CSCInfo(const char* credentialID, const char* certAlias, char** certificate);

CSC_RV CSCSendOTP(const char* credentialID);

CSC_RV CSCCredsAuth(const char* credentialID, int numSignatures, char** hash, const char* password, const char* otp, char** sad);

CSC_RV CSCSignHash(const char* credentialID, int numSignatures, char** hash, const char* sad, char** signature);

CSC_RV CSCAuthAndSign(const char* credentialID, int numSignatures, char** hash, const char* password, const char* otp);