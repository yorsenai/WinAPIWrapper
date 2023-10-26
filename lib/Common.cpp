#pragma once

#define _CRT_SECURE_NO_WARNINGS
#include <stdio.h>
#include <iostream>

#pragma comment(lib, "netapi32.lib")

#include <windows.h>
#include <lm.h>
#include <iostream>
#include <iomanip>
#include <lsalookup.h>
#include <ntsecapi.h>
#include <sddl.h>
#include <winbase.h>
#include <string>
#include <vector>

#define MAX_PRIVILEGE_INDEX 36

using namespace std;

const wchar_t* g_PrivilegeArray[] =
{
    TEXT("SeAssignPrimaryTokenPrivilege"),
    TEXT("SeAuditPrivilege"),
    TEXT("SeBackupPrivilege"),
    TEXT("SeChangeNotifyPrivilege"),
    TEXT("SeCreateGlobalPrivilege"),
    TEXT("SeCreatePagefilePrivilege"),
    TEXT("SeCreatePermanentPrivilege"),
    TEXT("SeCreateSymbolicLinkPrivilege"),
    TEXT("SeCreateTokenPrivilege"),
    TEXT("SeDebugPrivilege"),
    TEXT("SeEnableDelegationPrivilege"),
    TEXT("SeImpersonatePrivilege"),
    TEXT("SeIncreaseBasePriorityPrivilege"),
    TEXT("SeIncreaseQuotaPrivilege"),
    TEXT("SeIncreaseWorkingSetPrivilege"),
    TEXT("SeLoadDriverPrivilege"),
    TEXT("SeLockMemoryPrivilege"),
    TEXT("SeMachineAccountPrivilege"),
    TEXT("SeManageVolumePrivilege"),
    TEXT("SeProfileSingleProcessPrivilege"),
    TEXT("SeRelabelPrivilege"),
    TEXT("SeRemoteShutdownPrivilege"),
    TEXT("SeRestorePrivilege"),
    TEXT("SeSecurityPrivilege"),
    TEXT("SeShutdownPrivilege"),
    TEXT("SeSyncAgentPrivilege"),
    TEXT("SeSystemEnvironmentPrivilege"),
    TEXT("SeSystemProfilePrivilege"),
    TEXT("SeSystemtimePrivilege"),
    TEXT("SeTakeOwnershipPrivilege"),
    TEXT("SeTcbPrivilege"),
    TEXT("SeTimeZonePrivilege"),
    TEXT("SeTrustedCredManAccessPrivilege"),
    TEXT("SeUnsolicitedInputPrivilege"),
    TEXT("SeUndockPrivilege"),
    TEXT("SeInteractiveLogonRight"),
    TEXT("SeNetworkLogonRight")
};

LSA_HANDLE GetPolicyHandle() {
    LSA_OBJECT_ATTRIBUTES ObjectAttributes;
    USHORT SystemNameLength;
    LSA_UNICODE_STRING lusSystemName;
    NTSTATUS ntsResult;
    LSA_HANDLE lsahPolicyHandle;

    // Object attributes are reserved, so initialize to zeros.
    ZeroMemory(&ObjectAttributes, sizeof(ObjectAttributes));

    //Initialize an LSA_UNICODE_STRING to the server name.
    SystemNameLength = wcslen(L"");
    lusSystemName.Buffer = NULL;
    lusSystemName.Length = SystemNameLength * sizeof(WCHAR);
    lusSystemName.MaximumLength = (SystemNameLength + 1) * sizeof(WCHAR);

    // Get a handle to the Policy object.
    ntsResult = LsaOpenPolicy(
        &lusSystemName,    //Name of the target system.
        &ObjectAttributes, //Object attributes.
        POLICY_ALL_ACCESS, //Desired access permissions.
        &lsahPolicyHandle  //Receives the policy handle.
    );

    return lsahPolicyHandle;
}



bool InitLsaString(
    PLSA_UNICODE_STRING pLsaString,
    LPCWSTR pwszString
)
{
    DWORD dwLen = 0;

    if (NULL == pLsaString)
        return FALSE;

    if (NULL != pwszString)
    {
        dwLen = wcslen(pwszString);
        if (dwLen > 0x7ffe)   // String is too large
            return FALSE;
    }

    // Store the string.
    pLsaString->Buffer = (WCHAR*)pwszString;
    pLsaString->Length = (USHORT)dwLen * sizeof(WCHAR);
    pLsaString->MaximumLength = (USHORT)(dwLen + 1) * sizeof(WCHAR);

    return TRUE;
}


PSID GetSID(LPCTSTR Name) {
    DWORD dwSidLength = 0, dwLengthOfDomainName = 0, dwRetCode = 0;
    SID_NAME_USE typeOfSid;
    PSID lpSid = NULL;
    LPTSTR lpDomainName = NULL;

    if (!LookupAccountName(NULL, Name, NULL, &dwSidLength, NULL, &dwLengthOfDomainName, &typeOfSid)) {

        dwRetCode = GetLastError();
        //We don`t know the length of SID, that`s why we call this function twice
        if (dwRetCode == ERROR_INSUFFICIENT_BUFFER) {
            lpSid = (SID*) new char[dwSidLength];
            lpDomainName = (LPTSTR) new wchar_t[dwLengthOfDomainName];
        }
        else {
            cout << "Lookup account name failed: " << GetLastError() << endl;
            return NULL;
        }
    }

    if (!LookupAccountName(NULL, Name, lpSid, &dwSidLength, lpDomainName, &dwLengthOfDomainName, &typeOfSid)) {

        cout << "Lookup account name failed: " << GetLastError() << endl;
        return NULL;
    }
    return lpSid;
}