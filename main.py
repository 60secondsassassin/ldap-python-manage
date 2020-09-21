import ldap
import ldap.modlist
import getpass
from passlib.hash import ldap_salted_sha1 as ssha

## LDAP database global settings
## =============================
ldapURI =                         # e.g. : "ldap://example.org"
adminDN =                         # e.g. : "cn=Administrator,dc=example,dc=org"
peopleBaseDN =                    # e.g. : "ou=people,dc=example,dc=org"
groupBaseDN =                     # e.g. : "ou=group,dc=example,dc=org"
defaultUsersGID =                 # e.g. : "100"
defaultUserPassword =             # e.g. : "usersCreatedWithThisPassword"

## Search and List user or group
## =============================
def searchUserGroup(userGroupName,choice):
    searchScope = ldap.SCOPE_SUBTREE
    searchFilter = "cn="+ userGroupName
    
    if choice == "1":
        searchAttributes = ["uidNumber", "gidNumber"]
        return connect.search_s(peopleBaseDN, searchScope, searchFilter, searchAttributes)
        connect.unbind_s()
    
    if choice == "6":
        while 1:
            listmember = input("List group members ? (Y/N) .......... : ")
            if listmember in ["y", "Y", "n", "N"]:
                break
        if listmember in ["y", "Y"]:
            searchAttributes = ["member"]
        else:
            searchAttributes = ["gidNumber"]
        
        return connect.search_s(groupBaseDN, searchScope, searchFilter, searchAttributes)
        connect.unbind_s()

## Create user or group
## ====================
def createUserGroup(userGroupName,choice):
    if choice == "2":
        userFirstName = input("User first name ..................... : ")
        userLastName = input("User last name ...................... : ")
        while 1:
            userUID = input("User UID ............................ : ")
            if len(userUID) != 0:
                break
        
        if len(userLastName) == 0:
            userLastName = userGroupName
        
        createAttributes = {
            "objectClass": ["top".encode("utf-8"), "posixAccount".encode("utf-8"), "inetOrgPerson".encode("utf-8")],
            "uid": [userGroupName.encode("utf-8")],
            "givenName": [userFirstName.encode("utf-8")], # First name
            "sn": [userLastName.encode("utf-8")], # Last name
            "uidNumber": [userUID.encode("utf-8")],
            "homeDirectory": [str("/home/"+ userGroupName).encode("utf-8")],
            "loginShell": ["/bin/bash".encode("utf-8")],
            "gidNumber": [defaultUsersGID.encode("utf-8")],
            "description": ["Domain user".encode("utf-8")],
            "userPassword": [str(ssha.hash(defaultUserPassword)).encode("utf-8")],
            }
        
        connect.add_s("cn="+ userGroupName +","+ peopleBaseDN,ldap.modlist.addModlist(createAttributes))
        connect.unbind_s()
    
    if choice == "4":
        groupDescription = input("Group description ................... : ")
        while 1:
            groupIDNumber = input("Group GID ........................... : ")
            if len(groupIDNumber) != 0:
                break
        
        createAttributes = {
            "objectClass": ["top".encode("utf-8"), "posixGroup".encode("utf-8"), "groupOfNames".encode("utf-8")],
            "gidNumber": [groupIDNumber.encode("utf-8")],
            "description": ["Domain user".encode("utf-8")],
            }
        
        connect.add_s("cn="+ userGroupName +","+ groupBaseDN,ldap.modlist.addModlist(createAttributes))
        connect.unbind_s()

## Add/delete group member
## =======================
def addDeleteMember():
    userName = input("User name ........................... : ")
    groupName = input("Group name .......................... : ")
    userDN = str("cn="+ userName +","+ peopleBaseDN).encode("utf-8")
    
    if len(searchUserGroup(userName,"1")) == 0:
        print(userName +" doesn't exist")
    else:
        try:
            while 1:
                addDelete = input("Add member (a), Delete member (d) ... : ")
                if addDelete in ["a", "A", "d", "D"]:
                    break
            if addDelete in ["a", "A"]:
                connect.modify_s("cn="+ groupName +","+ groupBaseDN,[(ldap.MOD_ADD, "member", [userDN])])
            else:
                connect.modify_s("cn="+ groupName +","+ groupBaseDN,[(ldap.MOD_DELETE, "member", [userDN])])
        except ldap.NO_SUCH_OBJECT :
            print(groupName +" doesn't exist")
        except ldap.NO_SUCH_ATTRIBUTE :
            print(userName +" isn't member of "+ groupName)
        except ldap.TYPE_OR_VALUE_EXISTS :
            print(userName +" is already member of "+ groupName)
    connect.unbind_s()
    
## Update user's passsword
## =======================
def userPasswordUpdate(userGroupName):
    while 1:
        passwd1 = getpass.getpass("New password ........................ : ")
        passwd2 = getpass.getpass("Confirm new password ................ : ")
        
        if passwd1 == passwd2:
            break
        else:
            print("\n"+"Error ! - typing doesn't match."+"\n")
    
    oldPassword = {"userPassword": ["*"]}
    newPassword = {"userPassword": [str(ssha.hash(passwd1)).encode("utf-8")]}
    
    modifyAttributes = ldap.modlist.modifyModlist(oldPassword, newPassword)
    
    connect.modify_s("cn="+ userGroupName +","+ peopleBaseDN, modifyAttributes)
    connect.unbind_s()
    
## Delete a user or a group
## ========================
def deleteUserOrGroup(userGroupName):
    
    while 1:
        deleteUserGroup = input("Delete a user (u), a group (g) ...... : ")
        if deleteUserGroup in ["u", "U", "g", "G"]:
            break
    if deleteUserGroup in ["u", "U"]:
        connect.delete_s("cn="+ userGroupName +","+ peopleBaseDN)
    else:
        connect.delete_s("cn="+ groupBaseDN +","+ peopleBaseDN)
    connect.unbind_s()
    
## Launch operation
## ================
def exec():
    print()
    print("Search for a user ................... = 1")
    print("Create user ......................... = 2")
    print("Update user password ................ = 3")
    print("Create group ........................ = 4")
    print("Add/Delete group members ............ = 5")
    print("List groups or a group's members .... = 6")
    print("Delete a user or a group ............ = 7")
    print("Quit ................................ = 8")
    
    print()
    choice = input("Choose an operation ................. : ")
    print()
    
    if choice in ["1", "2", "3", "4", "6", "7"]:
        userGroupName = input("User or group unique ID ............. : ")
    
    # Search for user and list group members
    if choice in ["1", "6"]:
        if len(searchUserGroup(userGroupName,choice)) == 0:
            print("User or group doesn't exist")
            exec()
        else:
            print(searchUserGroup(userGroupName,choice))
            exec()
    
    # Create user or group
    elif choice in ["2", "4"]:
        if len(searchUserGroup(userGroupName,"1")) >= 1:
            print("User or group already exist")
            exec()
        else:
            createUserGroup(userGroupName,choice)
            exec()
    
    # Update user password
    elif choice == "3":
        if len(searchUserGroup(userGroupName,"1")) == 0:
            print("User doesn't exist")
            exec()
        else:
            userPasswordUpdate(userGroupName)
            exec()
    
    # Add/Delete group members
    elif choice == "5":
        addDeleteMember()
        exec()
    
    # Delete a user or a groug
    elif choice == "7":
        deleteUserOrGroup(userGroupName)
        exec()
    
    # Script ending
    elif choice == "8":
        print("Ending the script..."+"\n")
    
    else:
        print(choice +" is not a valid operation")
        exec()
    
## LDAP Connect
## ============
connect = ldap.initialize(ldapURI)

connect.set_option(ldap.OPT_PROTOCOL_VERSION, 3)
connect.set_option(ldap.OPT_X_TLS_REQUIRE_CERT, ldap.OPT_X_TLS_ALLOW)
connect.set_option(ldap.OPT_X_TLS_NEWCTX, 0)

while 1:
    print()
    adminPWD = getpass.getpass("LDAP administrator password ......... : ")
    try:
        connect.simple_bind_s(adminDN, adminPWD)
    except ldap.INVALID_CREDENTIALS:
        print("\n"+"Incorrect login or password")
    except ldap.SERVER_DOWN:
        print("\n"+"Unable to join server at " + ldapURI +"\n")
        break
    else:
        exec()
        break

