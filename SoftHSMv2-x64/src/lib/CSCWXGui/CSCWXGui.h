#pragma once

#define ERROR_DIALOG (0)
#define WARNING_DIALOG (1)

size_t CSCWXGui_GetCreds(char** userID, char** certAlias, char** password);

size_t CSCWXGui_GetOTPCode(char** code);

// On type you need to choose ERROR_DIALOG (default) or WARNING_DIALOG
size_t CSCWXGui_ErrorWarning(const char* title, const char* message, int type = ERROR_DIALOG);