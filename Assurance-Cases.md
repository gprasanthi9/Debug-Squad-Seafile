# Assurance Cases for Software Security Engineering

## Top-Level Claims

1. **Seafile Shared File Protection** (Kunle Amoo)
2. **Secure Login** (Erik Weinmeister)
3. **File Upload/Download Security** (Sreean Rikkala)
4. [Claim 4]
5. [Claim 5]

## Part 1: Breadth and Depth of Assurance Arguments

### 1.1 Seafile Shared File Protection (Kunle Amoo)
**Diagram:**  
[Diagram link]

**Assessment:**  


Seafile effectively minimizes the risk of unauthorized access to shared files during collaboration by enforcing a robust user authentication and authorization policy. This ensures that only authorized individuals can access and modify sensitive data, reducing the likelihood of a data breach. To further protect users' credentials, Seafile implements **[AES-256 encryption](https://help.seafile.com/security_and_encryption/use_encrypted_libraries/#:~:text=If%20you%20use%20web%20app,be%20found%20at%20Seafile%20Manual)** along with 1000 iterations of the **[SHA256 hash function](https://manual.seafile.com/security/security_features/)**, making it nearly impossible for attackers to hijack passwords through brute force or other common attack methods. Additionally, Seafile enhances its security with two-factor authentication **[2FA](https://manual.seafile.com/maintain/two_factor_authentication/)**, adding an extra layer of protection by requiring users to provide a second verification factor, significantly lowering the risk of unauthorized file access even if passwords are compromised.



**Assurance Case: File Sharing in Seafile**

- **Top-Level Claim (C1):** Seafile minimizes unauthorized disclosure of files during collaborative activities.
- **Context (CT1):** Seafile supports file lock.

### Supporting Arguments:

**Sub-Claims and evidence and others:**
- **Sub-Claim C1:** File access requires user Authentication
- **Sub-Claim C3:** Users' credentials are hashed 
- **Sub-Claim C4:** Seafile uses 2FA for file sharing
- **Sub-Claim C5:** Latest Seafile version supports 2FA

**Rebuttal:**
   - **R1:** Unless there is no proper access control.
   - **R2:** Unless The user's credentials are unprotected.
   - **R3:** Unless The system uses only passwords for authentication.
  
**Undermine**
   - **UM1:** Unless the version does not support 2FA
    
**Evidence:**  
   - E1: Seafile Audit report
   - E2: Seafile AES-256 encryption Implementation update.
   - E3: 2FA Code snippet.
   - E4: Seafile Forum Update.
       
  

### 1.2 Secure Login (Erik Weinmeister)

**Diagram:**  
[Diagram link]

**Assessment:**  
[Assessment text]


**Sub-Claim 1 and evidence and others:**



### 1.3 File Upload/Download Security (Sreean Rikkala)

**Diagram:**  
[Diagram link]

**Assessment:**  
Seafile keeps file uploads and downloads secure using **[AES-256 encryption](https://manual.seafile.com/security_features/encryption.html)** to protect data during transfer, and **[SSL/TLS protocols](https://manual.seafile.com/security_features/security_features.html)** to secure communication, preventing interception. It also uses **[role-based access control (RBAC)](https://manual.seafile.com/security_features/roles_permissions.html)** to ensure only authorized users can manage files. To avoid corruption, Seafile performs **[file integrity checks](https://manual.seafile.com/maintain/seafile_fsck.html)**, validating files and repairing any issues during transfer.


**Assurance Case: File Upload/Download Security in Seafile**

- **Top-Level Claim (C1):** Seafile ensures secure file uploads and downloads.
- **Context (CT1):** Seafile deployed in an enterprise environment.
- **Assumption (A1):** Users adhere to security policies.
- **Strategy (S1):** Argue over key security aspects of file upload/download process.
- **Justification (J1):** Aligns with industry-standard security measures.
- **Interface Rule (IR1):** Seafile adheres to secure file transfer protocols.

**Supporting Arguments:**

1. **Sub-Claim (C2):** Access to file operations is properly controlled.  
   **Evidence:**  
   - E1: Role-based access control implementation.  
   - E2: Multi-factor authentication logs.  
   **Rebuttal (R1):** Unless there's an unauthorized access attempt.

2. **Sub-Claim (C3):** Data is protected during file upload/download.  
   **Evidence:**  
   - E3: Encrypt File Transfer feature documentation.  
   - E4: AES-256 encryption implementation.  
   **Rebuttal (R2):** Unless there's a data interception attack.  
   **Sub-Claim (C8):** Robust encryption prevents data theft.  
   **Evidence:**  
   - E9: SSL/TLS implementation for secure data transmission.

3. **Sub-Claim (C4):** File integrity is maintained.  
   **Rebuttal (R3):** Unless there's file corruption during upload/download.  
   **Sub-Claim (C6):** File validation process documentation.  
   **Evidence:**  
   - E5: File validation process logs.  
   - E6: File Version Control system logs.

4. **Sub-Claim (C5):** Seafile actively updates security protocols.  
   **Evidence:**  
   - E7: Protocol version history and update logs.  
   - E8: Vulnerability response and patching records.  
   **Undercut (UC1):** Unless new protocol vulnerabilities emerge.



### 1.4 [Claim 4 Name]

**Diagram:**  
[Diagram link]

**Assessment:**  
[Assessment text]

**Sub-Claim 1 and evidence and others:**


### 1.5 [Claim 5 Name]

**Diagram:**  
[Diagram link]

**Assessment:**  
[Assessment text]

**Sub-Claim 1 and evidence and others:**

---

## Part 2: Evidence Alignment Observations

### 2.1 Seafile Shared File Protection

#### 2.1.1 Available Evidence
1. - E1: [Seafile Audit report](https://manual.seafile.com/security/auditing/)
     Seafile offers four audit logs in system admin panel in the Pro Edition:
       - Login log
       - File access log (including access to shared files)
       - File update log
       - Permission change log
      
2.   - E2: [Seafile AES-256 encryption Implementation update](https://manual.seafile.com/security/security_features/).
         - Seafile data is encrypted by the file key with AES 256/CBC. It uses PBKDF2 algorithm with [SHA256 Hash](https://manual.seafile.com/security/security_features/) to derive key/iv pair from the file key.
             After encryption, the data is uploaded to the server.
       
3. - E3: [2FA Code snippet](https://github.com/search?q=repo%3Ahaiwen%2Fseafile+2FA&type=code).
       - Beginning with Seafile version 6.0, Two-Factor Authentication (2FA) was introduced to strengthen account security.
         Administrators can enable this feature in two ways: either by selecting the appropriate checkbox under the 'Password' section of the system settings page,
         or by adding the following configuration to the seahub_settings.py file and restarting the service:
         ENABLE_TWO_FACTOR_AUTH = True
         TWO_FACTOR_DEVICE_REMEMBER_DAYS = 30  # optional, default is 90 days
         Once enabled, a 'Two-Factor Authentication' section will appear in the user's profile page,
         allowing users to scan a QR code with the Google Authenticator app on their smartphones for added security. 
   
4. - E4: [Seafile Forum Update] The available information in the [Forum](https://forum.seafile.com/t/seafile-8-0-x-with-webdav-and-2fa/17716).
     - shows that Seafile latest version supports 2FA to prentent unauthorized access to the shared files  
   
#### 2.1.2 Unavailable/Insufficient Evidence
1. All the evidences for this claim are available




### 2.2 [Claim 2 Name]

#### 2.2.1 Available Evidence
1. [Evidence 1]
2. [Evidence 2]

#### 2.2.2 Unavailable/Insufficient Evidence
1. [Missing evidence 1]
2. [Missing evidence 2]



### 2.3 File Upload/Download Security (Sreean Rikkala)

#### 2.3.1 Available Evidence
1. [Evidence 1]
2. [Evidence 2]

#### 2.3.2 Unavailable/Insufficient Evidence
1. [Missing evidence 1]
2. [Missing evidence 2]



### 2.4 [Claim 4 Name]

#### 2.4.1 Available Evidence
1. [Evidence 1]
2. [Evidence 2]

#### 2.4.2 Unavailable/Insufficient Evidence
1. [Missing evidence 1]
2. [Missing evidence 2]



### 2.5 [Claim 5 Name]

#### 2.5.1 Available Evidence
1. [Evidence 1]
2. [Evidence 2]

#### 2.5.2 Unavailable/Insufficient Evidence
1. [Missing evidence 1]
2. [Missing evidence 2]

---


## Planning & Reflection

### What We Did Well
* Active Participation: Our team has been showing regular updates to the project repository.
* Team is communicating much better with Whatsapp chat and during Zoom meetings
* Examined previous class's work to improve whole team understanding
  

### Areas for Improvement
* Consistency in Updates
* Expanded Analysis
* Synergies in data presentation

The Project Board can be found here: [Debug-Squad-Seafile](https://github.com/users/gprasanthi9/projects/3/views/1)
