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


typedef struct GroupInfo {
    LPWSTR gName;
    PSID gSID;

    vector<PWSTR> gPriveleges;
}gi_t;


class GroupManager {
    public:
        /*_______________GROUPS_________________*/

        vector<gi_t> Groups;


        void GetGroupPrivileges(LPWSTR groupname, PSID groupsid, vector<PWSTR>* priveleges) {

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

            NetUserGetInfo((LPCWSTR)pszServerName, groupname, 4, (LPBYTE*)&pTmpBuf1);

            NTSTATUS ntsResult;
            LSA_OBJECT_ATTRIBUTES ObjAttributes;
            LSA_HANDLE lsahPolicyHandle;
            ULONG count = 0;
            ZeroMemory(&ObjAttributes, sizeof(ObjAttributes));

            ntsResult = LsaOpenPolicy(0, &ObjAttributes, POLICY_LOOKUP_NAMES, &lsahPolicyHandle);
            PLSA_UNICODE_STRING rights;

            ntsResult = LsaEnumerateAccountRights(lsahPolicyHandle, groupsid, &rights, &count);
            ULONG u = LsaNtStatusToWinError(ntsResult);
            LPLOCALGROUP_INFO_0 lgroups = NULL;

            nStatusLG = NetUserGetLocalGroups((LPCWSTR)pszServerName, groupname, 0, LG_INCLUDE_INDIRECT,
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

        gi_t NewGroup_info(LPWSTR groupname, PSID groupsid) {
            gi_t tmp;
            tmp.gName = groupname;

            tmp.gSID = groupsid;
            
            GetGroupPrivileges(groupname, groupsid, &tmp.gPriveleges);


            return tmp;
        }


        void AddLocalGroup(wchar_t* groupName) {
            LOCALGROUP_INFO_0 groupInfo;
            groupInfo.lgrpi0_name = groupName;

            NET_API_STATUS status = NetLocalGroupAdd(NULL, 0, (PBYTE)&groupInfo, NULL);
            if (status == NERR_Success) {
                cout << "Success" << endl;

                this->Groups.push_back(NewGroup_info(groupInfo.lgrpi0_name, GetSID((LPCTSTR)groupName)));

            }
            else cout << "Error: " << GetLastError() << endl;
        }

        void DelLocalGroup(int index) {

            NET_API_STATUS status = NetLocalGroupDel(NULL, this->Groups[index].gName);
            if (status == NERR_Success) {
                cout << "Success" << endl;
                this->Groups.erase(this->Groups.begin() + index);

            }
            else cout << "Error: " << GetLastError() << endl;

        }

        void RemoveGroupPrivilege(int groupIndex) {

            DWORD privilegeAmount = 0;
            PLSA_UNICODE_STRING privilegeArray;
            LSA_HANDLE Handle = GetPolicyHandle();
            LsaEnumerateAccountRights(Handle, this->Groups[groupIndex].gSID, &privilegeArray, &privilegeAmount);

            LsaClose(Handle);

            if (privilegeAmount > 0) {
                for (size_t i = 0; i <= MAX_PRIVILEGE_INDEX; i++)
                    wcout << i << " - " << g_PrivilegeArray[i] << endl;;

                DWORD privilegeIndex = MAX_PRIVILEGE_INDEX + 1;
                while (privilegeIndex < 0 || privilegeIndex > MAX_PRIVILEGE_INDEX) {
                    cout << "Enter number of privilege: ";
                    wcin >> privilegeIndex;
                }

                LSA_OBJECT_ATTRIBUTES ObjAttributes;
                LSA_HANDLE lsahPolicyHandle;
                ZeroMemory(&ObjAttributes, sizeof(ObjAttributes));

                NTSTATUS ntsResult = LsaOpenPolicy(0, &ObjAttributes, POLICY_ALL_ACCESS, &lsahPolicyHandle);
                if (ntsResult != NULL)
                    cout << "Lsa open policy failed: " << GetLastError() << endl;

                LSA_UNICODE_STRING lsaString;
                InitLsaString(&lsaString, g_PrivilegeArray[privilegeIndex]);

                if (LsaRemoveAccountRights(lsahPolicyHandle, this->Groups[groupIndex].gSID, 0, &lsaString, 1) != NULL)
                    cout << "Error: " << GetLastError() << endl;
                else {
                    cout << "Success" << endl;
                    this->Groups[groupIndex].gPriveleges.clear();

                    GetGroupPrivileges(this->Groups[groupIndex].gName, this->Groups[groupIndex].gSID, &this->Groups[groupIndex].gPriveleges);
                }
            }
            else
                cout << "Group doesn't have any privileges" << endl;
        }

        void AddPrivilegeGroup(int index) {
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


            if (LsaAddAccountRights(lsahPolicyHandle, this->Groups[index].gSID, &lsaString, 1) != NULL)
                cout << "Error: " << GetLastError() << endl;
            else {
                cout << "Success" << endl;
                this->Groups[index].gPriveleges.push_back((PWSTR)g_PrivilegeArray[privilegeIndex]);//?
            }

        }


        /*_____________________________________*/
        /*_____________________________________*/
};