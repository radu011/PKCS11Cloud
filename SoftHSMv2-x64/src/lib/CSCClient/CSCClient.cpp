#define _CRT_SECURE_NO_WARNINGS

#include "CSCClient.h"

#include <stdio.h>
#include <stdlib.h>

#define CURL_STATICLIB

// "1.2.840.113549.1.1.1" RSA sign algo

#include "curl/curl.h" // https://curl.se/libcurl/c/
#include "cJson/cJSON.h" // https://github.com/DaveGamble/cJSON

typedef struct {
	char* baseURL;
}Info;

typedef struct {
	char* string;
	size_t size;
}Response;

#define ID_LENGTH 32

Info info;

size_t write_callback(void* data, size_t size, size_t nmemb, void* userdata)
{
	size_t realSize = size * nmemb;

	Response* response = (Response*)userdata;

	char* ptr = (char*)realloc(response->string, response->size + realSize + 1);
	if (ptr == NULL)
	{
		return CURL_WRITEFUNC_ERROR;
	}

	response->string = ptr;
	memcpy(&(response->string[response->size]), data, realSize);
	response->size += realSize;
	response->string[response->size] = '\0';

	return realSize;
}

CSC_RV exampleCURL()
{
	CURL* curl;
	CURLcode result;
	curl = curl_easy_init();
	if (curl == NULL) {
		//fprintf(stderr, "HTTP request failed\n");
		return -1;
	}

	Response response;
	response.string = (char*)malloc(1);
	response.size = 0;

	curl_easy_setopt(curl, CURLOPT_CUSTOMREQUEST, "POST");
	curl_easy_setopt(curl, CURLOPT_URL, "https://msign-test.transsped.ro/csc/v0/local/credentials/list");
	curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 1L);
	curl_easy_setopt(curl, CURLOPT_DEFAULT_PROTOCOL, "https");

	curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_callback);
	curl_easy_setopt(curl, CURLOPT_WRITEDATA, (void*)&response);

	struct curl_slist* headers = NULL;
	headers = curl_slist_append(headers, "Content-Type: application/json");
	curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
	const char* data = "{\"userID\":\"+40784122071\"}";
	curl_easy_setopt(curl, CURLOPT_POSTFIELDS, data);

	result = curl_easy_perform(curl);
	if (result != CURLE_OK)
	{
		//fprintf(stderr, "Error: %s\n", curl_easy_strerror(result));
		return -1;
	}

	//printf("%s\n", response.string);

	curl_easy_cleanup(curl);
	curl = NULL;
	curl_slist_free_all(headers);
	headers = NULL;
	data = NULL;

	free(response.string);

	return (int)result;
}

const char* createURL(const char* path) // baseURL + path
{
	char* newURL = (char*)malloc(sizeof(char) * (strlen(info.baseURL) + strlen(path) + 1));
	if (newURL == NULL)
		return NULL;

	sprintf(newURL, "%s/%s", info.baseURL, path);

	return newURL;
}

CSC_RV parseCSCList(char* string, char*** list)
{
	int count = 0;

	const cJSON* name = NULL;
	cJSON* monitor_json = cJSON_Parse(string);
	if (monitor_json == NULL)
	{
		const char* error_ptr = cJSON_GetErrorPtr();
		if (error_ptr != NULL)
		{
			//fprintf(stderr, "Error before: %s\n", error_ptr);
		}

		return CSC_JSON_PARSER_ERROR;
	}
	const cJSON* credentialIDs = cJSON_GetObjectItemCaseSensitive(monitor_json, "credentialIDs");
	if (credentialIDs == NULL)
	{
		return -1;
	}
	const cJSON* credentialID;
	cJSON_ArrayForEach(credentialID, credentialIDs)
	{
		if ((cJSON_IsString(credentialID)) && (credentialID->valuestring != NULL))
		{
			*list = (char**)realloc(*list, (count + 1) * (sizeof(char*)));
			if (*list == NULL)
				return CSC_MALLOC_ERROR;

			(*list)[count] = (char*)malloc(sizeof(char) * (strlen(credentialID->valuestring) + 1));
			if ((*list)[count] == NULL)
				return CSC_MALLOC_ERROR;

			memset((*list)[count], '\0', strlen(credentialID->valuestring) + 1);
			strcpy((*list)[count], credentialID->valuestring);

			count++;
		}
	}

	return count;
}

CSC_RV parseCSCInfoCertificate(const char* response, char** certificate)
{
	cJSON* json = cJSON_Parse(response);
	if (json == NULL)
	{
		const char* error_ptr = cJSON_GetErrorPtr();
		if (error_ptr != NULL)
		{
			//fprintf(stderr, "Error before: %s\n", error_ptr);
		}

		return CSC_JSON_PARSER_ERROR;
	}

	const cJSON* certSectionJson = NULL;
	certSectionJson = cJSON_GetObjectItemCaseSensitive(json, "cert");

	const cJSON* certificatesSectionJson = NULL;
	certificatesSectionJson = cJSON_GetObjectItemCaseSensitive(certSectionJson, "certificates");

	const cJSON* certificateJson = NULL;
	cJSON_ArrayForEach(certificateJson, certificatesSectionJson) {
		if (cJSON_IsString(certificateJson) && (certificateJson->valuestring != NULL))
		{
			*certificate = (char*)malloc(sizeof(char) * strlen(certificateJson->valuestring));
			if (*certificate == NULL)
			{
				// eroare
			}
			strcpy(*certificate, certificateJson->valuestring);
		}
	}

	return 0;
}

bool verifyCertAlias(const char* certAlias, const char* response)
{
	cJSON* json = cJSON_Parse(response);
	if (json == NULL)
	{
		const char* error_ptr = cJSON_GetErrorPtr();
		if (error_ptr != NULL)
		{
			//fprintf(stderr, "Error before: %s\n", error_ptr);
		}

		return CSC_JSON_PARSER_ERROR;
	}

	const cJSON* currentCertAlias = NULL;
	currentCertAlias = cJSON_GetObjectItemCaseSensitive(json, "description");
	if (cJSON_IsString(currentCertAlias) && (currentCertAlias->valuestring != NULL))
	{
		/*printf("Checking monitor \"%s\"\n", name->valuestring);*/
		// some problems
	}
	char* currentCertAliasStr = (char*)malloc(sizeof(char) * 64);
	if (currentCertAliasStr == NULL)
	{
		// eroare!
	}
	memset(currentCertAliasStr, '\0', 64);
	strcpy(currentCertAliasStr, currentCertAlias->valuestring + 12);

	//printf("~%s~\n", certAlias);
	//printf("~%s~\n", currentCertAliasStr);
	if (strcmp(certAlias, currentCertAliasStr) == 0)
	{
		return true;
	}

	return false;
}

CSC_RV CSCInit(const char* baseURL)
{
	size_t baseURLlen = strlen(baseURL);
	info.baseURL = (char*)malloc(sizeof(char) * (baseURLlen + 1));
	if (info.baseURL == NULL)
		return CSC_MALLOC_ERROR;

	memset(info.baseURL, '\0', baseURLlen + 1);
	strcpy(info.baseURL, baseURL);

	return CSC_SUCCESS;
}

CSC_RV CSCDestroy()
{
	free(info.baseURL);
	info.baseURL = NULL;

	return CSC_SUCCESS;
}

CSC_RV CSCList(const char* userID, char*** credentialIDs, int* noIDs)
{
	const char* requestURL = createURL("credentials/list");

	CURL* curl;
	CURLcode result;
	curl = curl_easy_init();
	if (curl == NULL) {
		//fprintf(stderr, "HTTP request failed\n");
		return CSC_CURL_INIT_ERROR;
	}

	Response response;
	response.string = (char*)malloc(1);
	response.size = 0;

	curl_easy_setopt(curl, CURLOPT_CUSTOMREQUEST, "POST");
	curl_easy_setopt(curl, CURLOPT_URL, requestURL);
	curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 1L);
	curl_easy_setopt(curl, CURLOPT_DEFAULT_PROTOCOL, "https");

	curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_callback);
	curl_easy_setopt(curl, CURLOPT_WRITEDATA, (void*)&response);

	struct curl_slist* headers = NULL;
	headers = curl_slist_append(headers, "Content-Type: application/json");
	curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);

	cJSON* monitor = cJSON_CreateObject();
	if (monitor == NULL)
		return CSC_JSON_PARSER_ERROR;
	if (cJSON_AddStringToObject(monitor, "userID", userID) == NULL)
		return CSC_JSON_PARSER_ERROR;
	char* data = cJSON_Print(monitor);
	if (data == NULL)
		return CSC_JSON_PARSER_ERROR;

	curl_easy_setopt(curl, CURLOPT_POSTFIELDS, data);

	result = curl_easy_perform(curl);
	if (result != CURLE_OK)
	{
		//fprintf(stderr, "Error: %s\n", curl_easy_strerror(result));
		return CSC_CURL_PERFORM_ERROR;
	}

	char** list = NULL;
	*noIDs = parseCSCList(response.string, &list);
	*credentialIDs = list;
	list = NULL;

	curl_easy_cleanup(curl);
	curl = NULL;
	curl_slist_free_all(headers);
	headers = NULL;
	free(response.string);
	cJSON_Delete(monitor);

	return CSC_SUCCESS;
}

CSC_RV CSCInfo(const char* credentialID, const char* certAlias, char** certificate)
{
	// crate specific url
	const char* requestURL = createURL("credentials/info");

	CURL* curl;
	CURLcode result;
	curl = curl_easy_init();
	if (curl == NULL) {
		//fprintf(stderr, "HTTP request failed\n");
		return CSC_CURL_INIT_ERROR;
	}

	Response response;
	response.string = (char*)malloc(1);
	response.size = 0;

	curl_easy_setopt(curl, CURLOPT_CUSTOMREQUEST, "POST");
	curl_easy_setopt(curl, CURLOPT_URL, requestURL);
	curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 1L);
	curl_easy_setopt(curl, CURLOPT_DEFAULT_PROTOCOL, "https");

	curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_callback);
	curl_easy_setopt(curl, CURLOPT_WRITEDATA, (void*)&response);

	struct curl_slist* headers = NULL;
	headers = curl_slist_append(headers, "Content-Type: application/json");
	curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);

	// create json format for request body
	cJSON* monitor = cJSON_CreateObject();
	if (monitor == NULL)
		return CSC_JSON_PARSER_ERROR;
	if (cJSON_AddStringToObject(monitor, "credentialID", credentialID) == NULL)
		return CSC_JSON_PARSER_ERROR;
	if (cJSON_AddStringToObject(monitor, "certInfo", "true") == NULL)
		return CSC_JSON_PARSER_ERROR;
	char* data = cJSON_Print(monitor);
	if (data == NULL)
		return CSC_JSON_PARSER_ERROR;

	curl_easy_setopt(curl, CURLOPT_POSTFIELDS, data);

	// call rest endpoint
	result = curl_easy_perform(curl);
	if (result != CURLE_OK)
	{
		//fprintf(stderr, "Error: %s\n", curl_easy_strerror(result));
		return CSC_CURL_PERFORM_ERROR;
	}

	// verify certificate alias
	//if (verifyCertAlias(certAlias, response.string) == false)
	//{
	//	// modificare ca sa dezaloc resursele
	//	return CSC_CERTIFICATE_ALIAS_MATCH_ERROR;
	//}
	// verify status of certificate (for valid)

	// extract certificate
	parseCSCInfoCertificate(response.string, certificate);

	curl_easy_cleanup(curl);
	curl = NULL;
	curl_slist_free_all(headers);
	headers = NULL;
	free(response.string);
	cJSON_Delete(monitor);

	return CSC_SUCCESS;
}

CSC_RV CSCSendOTP(const char* credentialID)
{
	const char* requestURL = createURL("credentials/sendOTP");

	CURL* curl;
	CURLcode res;
	curl = curl_easy_init();

	if (curl == NULL) {
		//fprintf(stderr, "HTTP request failed\n");
		return NULL;
	}
	curl_easy_setopt(curl, CURLOPT_CUSTOMREQUEST, "POST");
	curl_easy_setopt(curl, CURLOPT_URL, requestURL);
	curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 1L);
	curl_easy_setopt(curl, CURLOPT_DEFAULT_PROTOCOL, "https");

	struct curl_slist* headers = NULL;
	headers = curl_slist_append(headers, "Content-Type: application/json");
	curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);

	cJSON* monitor = cJSON_CreateObject();
	if (monitor == NULL)
		return CSC_JSON_PARSER_ERROR;
	if (cJSON_AddStringToObject(monitor, "credentialID", credentialID) == NULL)
		return CSC_JSON_PARSER_ERROR;
	char* data = cJSON_Print(monitor);
	if (data == NULL)
		return CSC_JSON_PARSER_ERROR;

	curl_easy_setopt(curl, CURLOPT_POSTFIELDS, data);
	res = curl_easy_perform(curl);

	curl_easy_cleanup(curl);
	curl = NULL;
	curl_slist_free_all(headers);
	headers = NULL;
	cJSON_Delete(monitor);

	return CSC_SUCCESS;
}

CSC_RV CSCCredsAuth(const char* credentialID, int numSignatures, char** hash, const char* password, const char* otp, char** sad)
{
	const char* requestURL = createURL("credentials/authorize");

	Response response;
	response.string = (char*)malloc(1);
	response.size = 0;

	CURL* curl;
	CURLcode res;
	curl = curl_easy_init();

	if (curl == NULL) {
		//fprintf(stderr, "HTTP request failed\n");
		return NULL;
	}

	curl_easy_setopt(curl, CURLOPT_CUSTOMREQUEST, "POST");
	curl_easy_setopt(curl, CURLOPT_URL, requestURL);
	curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 1L);
	curl_easy_setopt(curl, CURLOPT_DEFAULT_PROTOCOL, "https");

	curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_callback);
	curl_easy_setopt(curl, CURLOPT_WRITEDATA, (void*)&response);

	struct curl_slist* headers = NULL;
	headers = curl_slist_append(headers, "Content-Type: application/json");
	curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);

	cJSON* monitor = cJSON_CreateObject();
	if (monitor == NULL)
		return CSC_JSON_PARSER_ERROR;
	if (cJSON_AddStringToObject(monitor, "credentialID", credentialID) == NULL)
		return CSC_JSON_PARSER_ERROR;
	char numSignaturesStr[4];
	sprintf(numSignaturesStr, "%d", numSignatures);
	if (cJSON_AddStringToObject(monitor, "numSignatures", numSignaturesStr) == NULL)
		return CSC_JSON_PARSER_ERROR;
	// add hash list
	cJSON* hashes = cJSON_AddArrayToObject(monitor, "hash");
	if (hashes == NULL)
		return CSC_JSON_PARSER_ERROR;
	for (int i = 0; i < numSignatures; i++)
	{
		cJSON* element = cJSON_CreateString(hash[i]);
		cJSON_AddItemToArray(hashes, element);
	}

	if (cJSON_AddStringToObject(monitor, "PIN", password) == NULL)
		return CSC_JSON_PARSER_ERROR;
	if (cJSON_AddStringToObject(monitor, "OTP", otp) == NULL)
		return CSC_JSON_PARSER_ERROR;
	char* data = cJSON_Print(monitor);
	if (data == NULL)
		return CSC_JSON_PARSER_ERROR;

	// for test purpose
	//printf("\n\n%s\n\n", data);

	curl_easy_setopt(curl, CURLOPT_POSTFIELDS, data);
	res = curl_easy_perform(curl);

	// get SAD
	cJSON* monitorParser = cJSON_Parse(response.string);
	if (monitorParser == NULL)
	{
		const char* error_ptr = cJSON_GetErrorPtr();
		if (error_ptr != NULL)
		{
			//fprintf(stderr, "Error before: %s\n", error_ptr);
		}
	}
	cJSON* sadJSON = cJSON_GetObjectItemCaseSensitive(monitorParser, "SAD");
	if (cJSON_IsString(sadJSON) && (sadJSON->valuestring != NULL))
	{
		*sad = (char*)malloc(sizeof(char) * (strlen(sadJSON->valuestring) + 1));
		if (*sad == NULL)
			return CSC_MALLOC_ERROR;
		strcpy(*sad, sadJSON->valuestring);

		// for test purpose
		//printf("Checking monitor \"%s\"\n", sadJSON->valuestring);
	}
	else
		return CSC_JSON_PARSER_ERROR;

	curl_easy_cleanup(curl);
	curl = NULL;
	curl_slist_free_all(headers);
	headers = NULL;
	free(response.string);
	cJSON_Delete(monitor);

	return CSC_SUCCESS;
}

CSC_RV CSCSignHash(const char* credentialID, int numSignatures, char** hash, const char* sad, char** signature)
{
	const char* requestURL = createURL("signatures/signHash");

	Response response;
	response.string = (char*)malloc(1);
	response.size = 0;

	CURL* curl;
	CURLcode res;
	curl = curl_easy_init();

	if (curl == NULL) {
		//fprintf(stderr, "HTTP request failed\n");
		return NULL;
	}

	curl_easy_setopt(curl, CURLOPT_CUSTOMREQUEST, "POST");
	curl_easy_setopt(curl, CURLOPT_URL, requestURL);
	curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 1L);
	curl_easy_setopt(curl, CURLOPT_DEFAULT_PROTOCOL, "https");

	curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_callback);
	curl_easy_setopt(curl, CURLOPT_WRITEDATA, (void*)&response);

	struct curl_slist* headers = NULL;
	headers = curl_slist_append(headers, "Content-Type: application/json");
	curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);

	cJSON* monitor = cJSON_CreateObject();
	if (monitor == NULL)
		return CSC_JSON_PARSER_ERROR;
	if (cJSON_AddStringToObject(monitor, "credentialID", credentialID) == NULL)
		return CSC_JSON_PARSER_ERROR;
	if (cJSON_AddStringToObject(monitor, "signAlgo", "1.2.840.113549.1.1.11") == NULL)
		return CSC_JSON_PARSER_ERROR;
	if (cJSON_AddStringToObject(monitor, "signAlgoParams", "") == NULL)
		return CSC_JSON_PARSER_ERROR;
	if (cJSON_AddStringToObject(monitor, "hashAlgo", "2.16.840.1.101.3.4.2.1") == NULL)
		return CSC_JSON_PARSER_ERROR;

	cJSON* hashes = cJSON_AddArrayToObject(monitor, "hash");
	if (hashes == NULL)
		return CSC_JSON_PARSER_ERROR;
	for (int i = 0; i < numSignatures; i++)
	{
		cJSON* element = cJSON_CreateString(hash[i]);
		cJSON_AddItemToArray(hashes, element);
	}

	if (cJSON_AddStringToObject(monitor, "SAD", sad) == NULL)
		return CSC_JSON_PARSER_ERROR;

	char* data = cJSON_Print(monitor);
	if (data == NULL)
		return CSC_JSON_PARSER_ERROR;

	// for test purpose
	//printf("\n\n### signHash: %s\n\n", data);

	curl_easy_setopt(curl, CURLOPT_POSTFIELDS, data);
	res = curl_easy_perform(curl);

	// get signature
	cJSON* monitorParser = cJSON_Parse(response.string);
	if (monitorParser == NULL)
	{
		const char* error_ptr = cJSON_GetErrorPtr();
		if (error_ptr != NULL)
		{
			//fprintf(stderr, "Error before: %s\n", error_ptr);
		}
	}
	const cJSON* signaturesJson = cJSON_GetObjectItemCaseSensitive(monitorParser, "signatures");
	const cJSON* signatureJson = NULL;
	cJSON_ArrayForEach(signatureJson, signaturesJson) {
		if (cJSON_IsString(signatureJson) && (signatureJson->valuestring != NULL))
		{
			*signature = (char*)malloc(sizeof(char) * strlen(signatureJson->valuestring));
			if (*signature == NULL)
			{
				return CSC_MALLOC_ERROR;
			}
			strcpy(*signature, signatureJson->valuestring);
		}
	}

	curl_easy_cleanup(curl);
	curl = NULL;
	curl_slist_free_all(headers);
	headers = NULL;
	free(response.string);
	cJSON_Delete(monitor);

	return CSC_SUCCESS;
}

CSC_RV CSCAuthAndSign(const char* credentialID, int numSignatures, char** hash, const char* password, const char* otp)
{


	return CSC_SUCCESS;
}

CSC_RV mainTEST()
{
	//printf("%s\n", "Main test in CSCClient lib");

	/*char response[] = "{\n    \"description\": \"Card alias: CERTTest\",\n    \"key\": {\n        \"status\": \"enabled\",\n        \"algo\": [\n            \"1.2.840.113549.1.1.1\",\n            \"1.3.14.3.2.29\",\n            \"1.2.840.113549.1.1.11\",\n            \"1.2.840.113549.1.1.13\"\n        ],\n        \"len\": 2048\n    },\n    \"cert\": {\n        \"status\": \"valid\",\n        \"certificates\": [\n            \"MIIF1zCCBL+gAwIBAgIMZ6KOW3fLwW8ZQDnhMA0GCSqGSIb3DQEBCwUAMHQxCzAJ\r\nBgNVBAYTAlJPMRcwFQYDVQQKEw5UcmFucyBTcGVkIFNSTDEfMB0GA1UECxMWRk9S\r\nIFRFU1QgUFVSUE9TRVMgT05MWTErMCkGA1UEAxMiVHJhbnMgU3BlZCBNb2JpbGUg\r\nZUlEQVMgUUNBIC0gVEVTVDAeFw0yMzEwMjYxMDI2MjRaFw0yNTEwMjUxMDI2MjRa\r\nMIGQMQswCQYDVQQGEwJSTzEPMA0GA1UEBBMGVG9hZGVyMRQwEgYDVQQqEwtSYWR1\r\nLU1hcmlhbjE9MDsGA1UEBRM0MjAwNDEyMjM0VFIwRUVEMUY1MUNDMEQ5Njc2MTIw\r\nREM3OTJEMjIxNjY1QkZENDA2RTMyNzEbMBkGA1UEAxMSUmFkdS1NYXJpYW4gVG9h\r\nZGVyMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAkBNAf2ZU0RR5lY8K\r\nKYQpPeGnxf58QTk2nHATjI+t1P4gOobgDoKceUa49YGyj1obhH3TvHXCmNCBPAKT\r\nGjIYR1tGlUj2tx4lrcnrDAPszH1EGehGazV7RbRYEYqNanu/Ega5xCjB9rTS2QH9\r\nidVgePLRUFlq5qGHNTXskaB+CU9PXfTVZcfmn5QZ8ZlFXxeoMGQwdeFD33qc0xoa\r\nsH0/BMTraFONAxls6V3CAzx3rsOEo38FMPyiFPGTfU558YXMbBxJhAlDy4X7ypVg\r\nauIyikRsdb7DqRb2o9ysCnuVa+BHfUYaIIj2JKHIM5oQXQ6ZJr4nOuSEs6775u/N\r\nAeWxnwIDAQABo4ICSjCCAkYwgYQGCCsGAQUFBwEBBHgwdjBIBggrBgEFBQcwAoY8\r\naHR0cDovL3d3dy50cmFuc3NwZWQucm8vY2FjZXJ0cy90c19tb2JpbGVfZWlkYXNf\r\ncWNhX3Rlc3QucDdjMCoGCCsGAQUFBzABhh5odHRwOi8vb2NzcC10ZXN0LnRyYW5z\r\nc3BlZC5yby8wHQYDVR0OBBYEFM/xfd0gviWTNHBM/6ZSWE5+Iyb3MAwGA1UdEwEB\r\n/wQCMAAwHwYDVR0jBBgwFoAUCvGAR+TEUYHUKozGlW3pi3O1BMwwewYIKwYBBQUH\r\nAQMEbzBtMAgGBgQAjkYBATALBgYEAI5GAQMCAQswCAYGBACORgEEMBMGBgQAjkYB\r\nBjAJBgcEAI5GAQYBMDUGBgQAjkYBBTArMCkWI2h0dHBzOi8vd3d3LnRyYW5zc3Bl\r\nZC5yby9yZXBvc2l0b3J5EwJlbjBVBgNVHSAETjBMMD8GCysGAQQBgrgdBAEBMDAw\r\nLgYIKwYBBQUHAgEWImh0dHA6Ly93d3cudHJhbnNzcGVkLnJvL3JlcG9zaXRvcnkw\r\nCQYHBACL7EABAjBJBgNVHR8EQjBAMD6gPKA6hjhodHRwOi8vd3d3LnRyYW5zc3Bl\r\nZC5yby9jcmwvdHNfbW9iaWxlX2VpZGFzX3FjYV90ZXN0LmNybDAOBgNVHQ8BAf8E\r\nBAMCBsAwHQYDVR0lBBYwFAYIKwYBBQUHAwIGCCsGAQUFBwMEMCEGA1UdEQQaMBiB\r\nFnRvYWRlcnJhZHUyMUBnbWFpbC5jb20wDQYJKoZIhvcNAQELBQADggEBAInNkh9P\r\nddY+wO8LZy3C/IrHAh0P2dbTMPUiti7SYPbo6jVWXDauZ1lSsRizAu4dsz6yenEM\r\nfdZHH2LLzONNjao3B2UW3l4KSqXHmE/OEOHg9qUtf1mP7mM5D798ev88sdmiIQN6\r\nCIq3026FO/HLBrhRB+GMr2aixHQVbrwr4stJPquG9tndBm6THBS+N5jnnw+m76A/\r\nc3VJaMzyjyBAEC+Dk3wE7sHpAN7hRUr0Cq7NH6aa/U0JANh/0YdMGM9XPUAnwWzT\r\nf4J3X7cCgGM73Mi6rXpcklXM4YCOKho7bSyGgAyoLw2IYpZc4oj0/qWlDVIQFQ+i\r\nSmLSapUw5ZCUPRQ=\"\n        ],\n        \"issuerDN\": \"CN=Trans Sped Mobile eIDAS QCA - TEST,OU=FOR TEST PURPOSES ONLY,O=Trans Sped SRL,C=RO\",\n        \"serialNumber\": \"67a28e5b77cbc16f194039e1\",\n        \"subjectDN\": \"CN=Radu-Marian Toader,serialNumber=200412234TR0EED1F51CC0D9676120DC792D221665BFD406E327,givenName=Radu-Marian,SN=Toader,C=RO\",\n        \"validFrom\": \"20231026102624Z\",\n        \"validTo\": \"20251025102624Z\"\n    },\n    \"lang\": \"en-US\",\n    \"multisign\": true,\n    \"authMode\": \"oauth2code\",\n    \"SCAL\": \"2\"\n}";

	printf("Rezultat: %d\n", verifyCertAlias("CERTTest", response));

	char* certificate = NULL;
	printf("Rezultat 2: %d\n", parseCSCInfoCertificate(response, &certificate));*/


	// test semnare
	CSCInit("https://msign-test.transsped.ro/csc/v0/local");

	CSCSendOTP("55F89C2E8454ECAA5571B5BCED3F24B86A67A839");

	char* otpCode = (char*)malloc(sizeof(char) * 10);
	memset(otpCode, '\0', 10);
	scanf("%s", otpCode);

	char** hash = (char**)malloc(sizeof(char*) * 1);
	hash[0] = (char*)malloc(sizeof(char) * 64);
	memset(hash[0], '\0', 64);
	strcpy(hash[0], "ODVceufMhCfOuuRRx8YMhYzImMc2Z6LacdzWnUiPfvU=");

	char* SAD = NULL;

	CSCCredsAuth("55F89C2E8454ECAA5571B5BCED3F24B86A67A839",
		1,
		hash,
		"Radu21!",
		otpCode,
		&SAD
	);

	//printf("~SAD:%s~\n", SAD);
	char* signature = NULL;
	CSCSignHash("55F89C2E8454ECAA5571B5BCED3F24B86A67A839",
		1,
		hash,
		SAD,
		&signature);

	return CSC_SUCCESS;
}