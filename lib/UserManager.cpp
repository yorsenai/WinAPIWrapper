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

#include "Common.cpp"

using namespace std;


typedef struct UserInfo {
		LPWSTR uName;
		PSID uSID;
        string uLevel;

		vector<PWSTR> uPriveleges;
}ui_t;



class UserManager {
    public:
    /*_______________USERS_________________*/

    vector<ui_t> Users;

    void GetUserPrivileges(LPWSTR username, PSID usersid, vector<PWSTR>* priveleges) {

        LPUSER_INFO_0 pBuf = NULL;
        USER_INFO_1* tmpBuf;

        LPGROUP_USERS_INFO_1 pBuf1;
        LPLOCALGROUP_USERS_INFO_0 pBuf2;
        LPUSER_INFO_4 pTmpBuf1;
        NET_API_STATUS nStatus;
        NET_API_STATUS nStatusLG;

        DWORD dwEntriesRead = 0;
        DWORD dwEntriesRead1 = 0;
        DWORD dwEntriesReadLG = 0;
        DWORD dwTotalEntriesLG = 0;
        DWORD dwTotalEntries = 0;

        DWORD i = MAX_COMPUTERNAME_LENGTH + 1;
        DWORD dwTotalCount = 0;
        wchar_t pszServerName[MAX_COMPUTERNAME_LENGTH + 1];
        GetComputerNameW(pszServerName, &i);

        NetUserGetInfo((LPCWSTR)pszServerName, username, 4, (LPBYTE*)&pTmpBuf1);

        NTSTATUS ntsResult;
        LSA_OBJECT_ATTRIBUTES ObjAttributes;
        LSA_HANDLE lsahPolicyHandle;
        ULONG count = 0;
        ZeroMemory(&ObjAttributes, sizeof(ObjAttributes));

        ntsResult = LsaOpenPolicy(0, &ObjAttributes, POLICY_LOOKUP_NAMES, &lsahPolicyHandle);
        PLSA_UNICODE_STRING rights;

        ntsResult = LsaEnumerateAccountRights(lsahPolicyHandle, usersid, &rights, &count);
        ULONG u = LsaNtStatusToWinError(ntsResult);
        LPLOCALGROUP_INFO_0 lgroups = NULL;

        nStatusLG = NetUserGetLocalGroups((LPCWSTR)pszServerName, username, 0, LG_INCLUDE_INDIRECT,
            (LPBYTE*)&pBuf2, MAX_PREFERRED_LENGTH, &dwEntriesReadLG, &dwTotalEntriesLG);

        if (ntsResult == ERROR_SUCCESS) {
            if (count) {
                for (int k = 0; k < count; k++) {

                    priveleges->push_back(rights->Buffer);
                    rights++;

                }
            }
            else { cout << "None"; }
        }
        
        else {
            dwEntriesRead = 0;
            dwTotalEntries = 0;

            nStatus = NetLocalGroupEnum(pszServerName, 0, (LPBYTE*)&lgroups, MAX_PREFERRED_LENGTH,
                &dwEntriesRead, &dwTotalEntries, 0);

            if (dwEntriesReadLG != 0 && nStatus == NERR_Success && nStatusLG == NERR_Success) {
                LPLOCALGROUP_USERS_INFO_0 pTmpBuf = pBuf2;
                for (int i = 0; i < dwEntriesRead; i++) {
                    if (lstrcmpW(lgroups->lgrpi0_name, pTmpBuf->lgrui0_name) == 0) {
                        LSA_HANDLE lsahPolicyHandle;
                        LSA_OBJECT_ATTRIBUTES ObjAttributes;


                        ZeroMemory(&ObjAttributes, sizeof(ObjAttributes));
                        ntsResult = LsaOpenPolicy(0, &ObjAttributes, POLICY_ALL_ACCESS, &lsahPolicyHandle);
                        PLSA_UNICODE_STRING rights;
                        ULONG count = 0;
                        ntsResult = LsaEnumerateAccountRights(lsahPolicyHandle, GetSID(lgroups->lgrpi0_name), &rights, &count);
                        if (ntsResult == ERROR_SUCCESS) {
                            if (count) {
                                for (int k = 0; k < count; k++) {

                                    priveleges->push_back(rights->Buffer);
                                    rights++;
                                }
                            }
                            else { cout << "None"; }
                        }
                    }
                    lgroups++;
                }
            }
        }
        
        cout << endl;
    }

    ui_t NewUser_info(LPWSTR username, PSID usersid, DWORD userpriv) {
        ui_t tmp;
        tmp.uName = username;
        tmp.uSID = usersid;

        switch (userpriv) {
        case USER_PRIV_GUEST: { tmp.uLevel = "GUEST"; break; }
        case USER_PRIV_USER: { tmp.uLevel = "USER"; break; }
        case USER_PRIV_ADMIN: {tmp.uLevel = "ADMIN"; break; }
        default: { tmp.uLevel = "Unknown";  break; }
        }
        GetUserPrivileges(username, usersid, &tmp.uPriveleges);


        return tmp;
    }

    

    void AddUser(TCHAR* userName, TCHAR* userPassword) {
        

        USER_INFO_1 userInfo;
        NET_API_STATUS nStatus = NERR_Success;
        ZeroMemory(&userInfo, sizeof(USER_INFO_1));
        userInfo.usri1_name = userName;
        userInfo.usri1_password = userPassword;
        userInfo.usri1_priv = USER_PRIV_USER;
        userInfo.usri1_flags = UF_NORMAL_ACCOUNT | UF_SCRIPT;

        nStatus = NetUserAdd(NULL, 1, (PBYTE)&userInfo, NULL);

        if (nStatus == NERR_Success) {
            cout << "Success" << endl;
            this->Users.push_back(NewUser_info(userName, GetSID(userName), USER_PRIV_USER));
        }
        else {
            cout << "Error: " << GetLastError() << endl;
        }

        //UpdateBase();
    }

    void DeleteUser(unsigned int index) {
        

        NET_API_STATUS nStatus = NetUserDel(NULL, this->Users[index].uName);

        if (nStatus == NERR_Success) {
            cout << "Success" << endl;
            this->Users.erase(this->Users.begin() + index);

        }
        else {
            cout << "Error: " << GetLastError() << endl;
        }

        //UpdateBase();
    }

    void RemoveUserPrivilege(unsigned int userIndex) {

        DWORD privilegesAmount = 0;
        PLSA_UNICODE_STRING privilegesArray;
        LSA_HANDLE Handle = GetPolicyHandle();
        LsaEnumerateAccountRights(Handle, this->Users[userIndex].uSID, &privilegesArray, &privilegesAmount);
        LsaClose(Handle);

        if (privilegesAmount > 0) {

            cout << "Privilege list" << endl;
            for (int i = 0; i <= MAX_PRIVILEGE_INDEX; i++)
                wcout << i << ". " << g_PrivilegeArray[i] << endl;

            DWORD privilegeIndex = MAX_PRIVILEGE_INDEX + 1;
            while (privilegeIndex < 0 || privilegeIndex > MAX_PRIVILEGE_INDEX) {
                cout << endl << "Enter number of privilege: ";
                wcin >> privilegeIndex;
            }

            LSA_UNICODE_STRING lsaString;
            InitLsaString(&lsaString, g_PrivilegeArray[privilegeIndex]);

            LSA_HANDLE pHandle = GetPolicyHandle();
            NTSTATUS nStatus = LsaRemoveAccountRights(pHandle, this->Users[userIndex].uSID, FALSE, &lsaString, 1);
            LsaClose(pHandle);

            if (LsaNtStatusToWinError(nStatus) == ERROR_SUCCESS) {
                cout << "Success" << endl;

                this->Users[userIndex].uPriveleges.clear();

                GetUserPrivileges(this->Users[userIndex].uName, this->Users[userIndex].uSID, &this->Users[userIndex].uPriveleges);

            }
            else {
                cout << "Error: " << GetLastError() << endl;
            }

        }
        else
            cout << "User doesn't have any privileges" << endl;
    }

    void AddPrivilegeUser(int index) {


        LSA_HANDLE lsahPolicyHandle;
        LSA_OBJECT_ATTRIBUTES ObjAttributes;
        ZeroMemory(&ObjAttributes, sizeof(ObjAttributes));

        NTSTATUS ntsResult = LsaOpenPolicy(0, &ObjAttributes, POLICY_ALL_ACCESS, &lsahPolicyHandle);
        if (ntsResult != NULL)
            cout << "Lsa open policy failed: " << GetLastError() << endl;

        for (size_t i = 0; i <= MAX_PRIVILEGE_INDEX; i++)
            wcout << i << " - " << g_PrivilegeArray[i] << endl;

        DWORD privilegeIndex = MAX_PRIVILEGE_INDEX + 1;
        while (privilegeIndex < 0 || privilegeIndex > MAX_PRIVILEGE_INDEX) {
            cout << "Enter number of privilege: ";
            wcin >> privilegeIndex;
        }

        LSA_UNICODE_STRING lsaString;
        InitLsaString(&lsaString, g_PrivilegeArray[privilegeIndex]);

        if (LsaAddAccountRights(lsahPolicyHandle, this->Users[index].uSID, &lsaString, 1) != NULL)
            cout << "Error: " << GetLastError() << endl;
        else {
            cout << "Success" << endl;
            this->Users[index].uPriveleges.push_back((PWSTR)g_PrivilegeArray[privilegeIndex]);
        }

    }

    /*_____________________________________*/
    /*_____________________________________*/

};