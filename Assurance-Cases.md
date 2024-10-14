# Assurance Cases for Software Security Engineering

## Top-Level Claims

1. [Claim 1]
2. **Secure Login** (Erik Weinmeister)
3. **File Upload/Download Security** (Sreean Rikkala)
4. [Claim 4]
5. [Claim 5]

## Part 1: Breadth and Depth of Assurance Arguments

### 1.1 [Claim 1 Name]

**Diagram:**  
[Diagram link]

**Assessment:**  
[Assessment text]

**Sub-Claim 1 and evidence and others:**



### 1.2 Secure Login (Erik Weinmeister)

**Diagram:**  
[Diagram link]

**Assessment:**  
Secure logins are provided with username and passwords. If users follow password policy they have the first level of protection.  If that is compromised the second layer of multi factor authentication via a key fob is providing protection.  In the case a user surrenders the password and the key fob, they are to report it.  When this is reported remote login is disabled and a password change is enacted.  The other avenue of a password spraying attack that would lead to mutiple prompts to the user for MFA, can lead to MFA fatigue.  This is when the user gets so many requests they just approve them.  The multiple failures in the logs from the spray attack will see a failure and should be looking for successes to trigger a account lockout, which will send an alert.

Assurance Case: File Upload/Download Security in Seafile
- **Top-Level Claim (C1):** Seafile Secure Login.
- **Context (CT1):** Seafile users are normal (non-technical).
- **Rebuttal (R1):** Unless User is not following password policy
**Supporting Arguments:**
1.	**Sub-Claim (C2):** MFA prevents password compromise.
Evidence:
-	R2: Unless the user loses key fob and also shared the password.
-	R3: Unless the user is experiencing MFA fatigue and verifies every prompt
2.	**Sub-Claim (C3):** User reported key fob loss.
Evidence:
-	E1: Remote login Disabled.
-	E2: Password change.

3.	**Sub-Claim (C4):** User is trained to only provide MFA when the know it is in response to their action
- Evidence (E3):  Multiple simultaneous failures from logs
- Undermine (UM1): Unless log was only looking for failures
4.	**Sub-Claim (C5):** Multiple failures disable account.
- Evidence (E4):  Alerts for locked account



### 1.3 File Upload/Download Security (Sreean Rikkala)

**Diagram:**  
![Assurance Case: File Upload/Download Security in Seafile](https://github.com/gprasanthi9/Debug-Squad-Seafile/blob/bd048497ef19f401f23cff9937ea8d13e6a5ef47/Assurance%20Case%20Diagram/File%20Upload%26Download.drawio.png)

**Assessment:**  
Seafile keeps file uploads and downloads secure using **[AES-256 encryption](https://manual.seafile.com/security_features/encryption.html)** to protect data during transfer, and **[SSL/TLS protocols](https://manual.seafile.com/security_features/security_features.html)** to secure communication, preventing interception. It also uses **[role-based access control (RBAC)](https://manual.seafile.com/security_features/roles_permissions.html)** to ensure only authorized users can manage files. To avoid corruption, Seafile performs **[file integrity checks](https://manual.seafile.com/maintain/seafile_fsck.html)**, validating files and repairing any issues during transfer.


**Assurance Case: File Upload/Download Security in Seafile**

- **Top-Level Claim (C1):** Seafile ensures secure file uploads and downloads
- **Context (CT1):** Seafile deployed in enterprise environment
- **Assumption (A1):** Users adhere to security policies
- **Strategy (S1):** Argue over key security aspects of file upload/download process
- **Justification (J1):** Aligns with industry-standard security measures
- **Interface Rule (IR1):** Seafile adheres to secure file upload/download protocols

**Supporting Arguments:**
1. **Sub-Claim (C1):** Access to file operations is properly controlled  
   **Evidence:**  
   - E1: Role-based access control implementation  
   - E2: Multi-factor authentication logs  
   **Rebuttal (R1):** Unless there's an unauthorized access attempt  
   **Sub-Claim (C5):** Access control mitigates unauthorized access  
   **Evidence:**  
   - E7: Failed access attempt logs

2. **Sub-Claim (C2):** Data is protected during file upload/download  
   **Evidence:**  
   - E3: SSL/TLS implementation for transfers  
   - E4: AES-256 encryption implementation  
   **Rebuttal (R2):** Unless there's a data interception attack  
   **Sub-Claim (C6):** Robust encryption prevents data theft  
   **Evidence:**  
   - E8: SSL/TLS implementation for secure data transmission

3. **Sub-Claim (C3):** File integrity is maintained  
   **Rebuttal (R3):** Unless there's a file corruption during upload/download  
   **Sub-Claim (C7):** File validation ensures data integrity  
   **Evidence:**  
   - E9: File validation process documentation

4. **Sub-Claim (C4):** Seafile actively updates security protocols  
   **Evidence:**  
   - E5: Protocol version history and update logs  
   - E6: Vulnerability response and patching records

**Undercut (UC1):** Unless new protocol vulnerabilities emerge



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

### 2.1 [Claim 1 Name]

#### 2.1.1 Available Evidence
1. [Evidence 1]
2. [Evidence 2]

#### 2.1.2 Unavailable/Insufficient Evidence
1. [Missing evidence 1]
2. [Missing evidence 2]



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
