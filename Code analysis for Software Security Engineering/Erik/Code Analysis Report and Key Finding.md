# SEAFILE CODE REVIEW FOR SECURITY RISKS ASSESSMENT
**Date:** December 8, 2024  
**Project:** Seafile Server  
**Focus:** Seafile-server  
**Repository:** [Seafile-server GitHub](https://github.com/haiwen/seafile-server)  

## Utilize integrated CodeQL
Followed the steps from our Code Security-Github module https://unomaha.instructure.com/courses/81794/pages/code-security-github?module_item_id=3125845
Discovered this was not able to scan C code, confirmed by Dr. Gandhi
## Utilxe Devskim (was listed under Other Tools)
DevSkim fourn 905 erros (was lots of duplicates), identified 5 distinct ones



## 3. HARD-DODED CREDENTIALS (CWE-798)
**Location:** `server/seaf-db.c`  
**Location Link:** [View Code](https://github.com/haiwen/seafile-server/blob/master/common/seaf-db.c#L864)  
**Risk Level:** High  
**Found In Code:** `if (!mysql_real_connect(db_conn, db->host, db->user, db->password,`  

### Details:
 -  Database credentials exposed in configuration
 -  Hard-coded connection strings
 -	Insecure credential storage
 -  Poor secrets management
 
CWE-798 is a vulnerability of of hard coding credentials, the actual file location is https://github.com/haiwen/seafile-server/blob/master/common/seaf-db.c#L864  and is the seaf-db file line 864

Upon manual inspection of seaf-db.c is line 864, this is a test to see if the connection to the database fails, if it does it returns an warning message and closes the connection.  The method of the connection appears at first glance to send a clear text password of “password”.  Further analysis of “db->password” in the subsequent code shows this is an alternate way of passing a variable.

### Line 792 - db->password = g_strdup (password);
    set this db->password from the g_strdup(password)
### Line 780 - const char *password,
    set the password const(means pointer to character cannot change) as char(character) *(pointer)
### Line 753 -     char *password;
	Part of setting up the database and defines a char field for password
### 749 is “typedef struct MySQLDB”
    struct SeafDB parent;

### Line 67 – const char *password,

### Line 64 – “mysql_db_new (const char *host,”
    There is a variable called g_strdup(password) being set to the password to the mysql database on line 792

## Result - False positive
 Does not appear the code is setting the password in the code and it is not using “password” as a password, it only uses it as a variable or field name.
