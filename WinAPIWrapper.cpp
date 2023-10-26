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

#include "lib/UserManager.cpp"
#include "lib/GroupManager.cpp"
// #include "Common.cpp"

using namespace std;



class WinApiWrapper {
private:
    
    /*_______________COMMON_________________*/

	const enum ACCEPTABLE_COMMANDS { SHLIST_USR = 1, ADD_USR = 2, DEL_USR = 3, ADDPRIV_USR = 4, DELPRIV_USR = 5,
                                     SHLIST_LGR = 6, ADD_LGR = 7, DEL_LGR = 8, ADDPRIV_LGR = 9, DELPRIV_LGR = 10,
    
                                     EXT_ALL = 0, CLS_ALL = 100                                                };


    int ConfirmChoise(string target, string action) {

        unsigned int index;

        while (true) {

            cout << "Enter the index of " << target << " you want to " << action << ": ";
            cin >> index;
            if (index > 0) {
                index--;
            }
            cout << "Proceed to " << action << " " << target << " <";
            if (target == "group") {
                wprintf(this->GM.Groups[index].gName);
            }
            else if (target == "user") {

                wprintf(this->UM.Users[index].uName);
            }

            cout << ">? (press y to continue or any other key to cancel)\n>>";
            char conf;
            cin >> conf;
            if (conf == 'y') {
                break;
            }
            else {
                cout << "Canceling. Please try again." << endl;
            }
        }

        return index;


    }

    /*_____________________________________*/
    /*_____________________________________*/

    // vector<ui_t> Users;
    // vector<gi_t> Groups;

    UserManager UM;
    GroupManager GM;




	

public:

    WinApiWrapper() { 

        DWORD usersAmount;
        DWORD groupsAmount;

        USER_INFO_1* winUsersArray;
        LOCALGROUP_INFO_0* winGroupsArray;

        DWORD dwtotalentries;

        NetUserEnum(NULL, 1, (DWORD)0, (LPBYTE*)&winUsersArray, (DWORD)-1, &usersAmount, &dwtotalentries, NULL);

        NetLocalGroupEnum(NULL, 0, (LPBYTE*)&winGroupsArray, (DWORD)-1, &groupsAmount, &dwtotalentries, NULL);

        for (int i = 0; i < usersAmount; i++) {

            this->UM.Users.push_back(this->UM.NewUser_info(winUsersArray[i].usri1_name, GetSID((LPCTSTR)winUsersArray[i].usri1_name), winUsersArray[i].usri1_priv));
        }

        for (int i = 0; i < groupsAmount; i++) {

            this->GM.Groups.push_back(this->GM.NewGroup_info(winGroupsArray[i].lgrpi0_name, GetSID((LPCTSTR)winGroupsArray[i].lgrpi0_name)));
        }


    };

    ~WinApiWrapper() {

        this->UM.Users.clear();
        this->GM.Groups.clear();  
    }



	void execute_command(int cmd) {

        switch (cmd) {
            case SHLIST_USR : {
                int counter = 0;
                for (ui_t user : this->UM.Users) {
                    counter++;
                    LPWSTR s;
                    ConvertSidToStringSidW(user.uSID, &s);

                    cout << "--- USER #"<< counter <<" ---\nUser Name: ";
                    wprintf(user.uName);

                    cout << "\nUser SID: ";
                    wprintf(s);

                    cout << "\nUser Priveleges : {";
                    if (user.uPriveleges.empty()) {
                        cout << "--None--" << endl;
                    }
                    else {
                        for (PWSTR elem : user.uPriveleges) {

                            cout << "\t--";
                            wprintf(elem);
                            cout << "--" << endl;

                        }
                    }
                    cout << " }\nUser level: " << user.uLevel<<"\n\n" << endl;
                }
                break;
            }
            
            case ADD_USR:{
                TCHAR userName[128] = { 0 };
                TCHAR userPassword[128] = { 0 };

                cout << "Enter name of new user: ";
                wcin >> userName;
                cout << "Enter password of new user: ";
                wcin >> userPassword;

                this->UM.AddUser(userName, userPassword);
                break;
            }
            case DEL_USR: {
                unsigned int index = ConfirmChoise("user", "delete");
                this->UM.DeleteUser(index);
                break;
            }
            case ADDPRIV_USR:{

                unsigned int index = ConfirmChoise("user", "add privilege to");


                this->UM.AddPrivilegeUser(index);
                break;
            }
            case DELPRIV_USR: {
                unsigned int index = ConfirmChoise("user", "remove privilege from");

                this->UM.RemoveUserPrivilege(index);
                break;

            }
            case SHLIST_LGR: {
                int counter = 0;

                for (gi_t group : this->GM.Groups) {
                    counter++;

                    LPWSTR s;
                    ConvertSidToStringSidW(group.gSID, &s);

                    cout << "--- GROUP #" << counter << " ---\nGroup Name: ";

                    wprintf(group.gName);

                    cout << "\nGroup SID: ";
                    wprintf(s);

                    cout << "\nGroup Priveleges : {";
                    if (group.gPriveleges.empty()) {
                        cout << "--None--" << endl;
                    }
                    else {
                        for (PWSTR elem : group.gPriveleges) {

                            cout << "\t--";
                            wprintf(elem);
                            cout << "--" << endl;

                        }
                    }
                    cout << "}\n\n";
                }
                break;

            }
            case ADD_LGR: {
                wchar_t groupName[128];
                wcout << "Enter the name of new group: ";
                wcin >> groupName;

                this->GM.AddLocalGroup(groupName);
                break;

            }
            case DEL_LGR: {
                unsigned int index = ConfirmChoise("group", "delete");

                this->GM.DelLocalGroup(index);
                break;
            }
            case ADDPRIV_LGR: {
                
                unsigned int index = ConfirmChoise("group", "add privilege to");

                this->GM.AddPrivilegeGroup(index);
                break;


            }
            case DELPRIV_LGR: {
                unsigned int index = ConfirmChoise("group", "remove privilege from");

                this->GM.RemoveGroupPrivilege(index);
                break;

            }
            case CLS_ALL:{
                system("cls");
                break;
            }
            case EXT_ALL: {
                exit(0);
                break;
            }
            default: {
                cout << "Unknown command" << endl;
                break;
            }
        }

		return;
	}
};



int main() {
    setlocale(LC_ALL, "Rus");
	WinApiWrapper WAW;
	int command;
    system("cls");
	while (true) {

        cout << "Choose a command to execute:" << endl; 
        cout << "1. Show list of users\n2. Add new user\n3. Delete user\n4. Give priveleges to user\n5. Remove privelege from user\n" << endl;
        cout << "6. Show list of groups\n7. Add new group\n8. Delete group\n9. Give priveleges to group\n10. Remove privelege from group\n" << endl;
        cout << "0. Exit\n100. Clear\n" << endl;
        cout << ">> ";
		cin >> command;
        WAW.execute_command(command);
	}

}
