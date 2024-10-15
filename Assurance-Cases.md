# Assurance Cases for Software Security Engineering

## Top-Level Claims

1. [Claim 1]
2. **Secure Login** (Erik Weinmeister)
3. **File Upload/Download Security** (Sreean Rikkala)
4. **File Version Control** (Anjani Monica Sai Allada)
5. [Claim 5]

## Part 1: Breadth and Depth of Assurance Arguments

### 1.1 [Claim 1 Name]

**Diagram:**  
[Diagram link]

**Assessment:**  
[Assessment text]

**Sub-Claim 1 and evidence and others:**


----
### 1.2 Secure Login (Erik Weinmeister)
 
![Assurance Case: File Upload/Download Security in Seafile](https://github.com/gprasanthi9/Debug-Squad-Seafile/blob/main/Assurance%20Case%20Diagram/LoginAssuranceCaseV2.jpg)

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

----
### 1.3 File Upload/Download Security (Sreean Rikkala)

![Assurance Case: File Upload/Download Security in Seafile](https://github.com/gprasanthi9/Debug-Squad-Seafile/blob/bd048497ef19f401f23cff9937ea8d13e6a5ef47/Assurance%20Case%20Diagram/File%20Upload%26Download.drawio.png)

**Assessment:**  
Seafile keeps file uploads and downloads secure using **[AES-256 encryption](https://manual.seafile.com/security_features/encryption.html)** to protect data during transfer, and **[SSL/TLS protocols](https://manual.seafile.com/security_features/security_features.html)** to secure communication, preventing interception. It also uses **[role-based access control (RBAC)](https://manual.seafile.com/security_features/roles_permissions.html)** to ensure only authorized users can manage files. To avoid corruption, Seafile performs **[file integrity checks](https://manual.seafile.com/maintain/seafile_fsck.html)**, validating files and repairing any issues during transfer.


- **Top-Level Claim (C1):** Seafile ensures secure file uploads and downloads
- **Context (CT1):** Seafile deployed in enterprise environment
- **Assumption (A1):** Users adhere to security policies
- **Strategy (S1):** Argue over key security aspects of file upload/download process
- **Justification (J1):** Aligns with industry-standard security measures
- **Interface Rule (IR1):** Seafile adheres to secure file upload/download protocols

**Supporting Arguments:**

1. **Sub-Claim (C1):** Access to file operations is properly controlled
   - **Evidence:**
     - E1: Role-based access control implementation
     - E2: Multi-factor authentication logs
   - **Rebuttal (R1):** Unless there's an unauthorized access attempt
     - **Sub-Claim (C5):** Access control mitigates unauthorized access
       - **Evidence:** E7: Failed access attempt logs

2. **Sub-Claim (C2):** Data is protected during file upload/download
   - **Evidence:**
     - E3: SSL/TLS implementation for transfers
     - E4: AES-256 encryption implementation
   - **Rebuttal (R2):** Unless there's a data interception attack
     - **Sub-Claim (C6):** Robust encryption prevents data theft
       - **Evidence:** E8: SSL/TLS implementation for secure data transmission

3. **Sub-Claim (C3):** File integrity is maintained
   - **Rebuttal (R3):** Unless there's a file corruption during upload/download
     - **Sub-Claim (C7):** File validation ensures data integrity
       - **Evidence:** E9: File validation process documentation

4. **Sub-Claim (C4):** Seafile actively updates security protocols
   - **Evidence:**
     - E5: Protocol version history and update logs
     - E6: Vulnerability response and patching records

- **Undercut (UC1):** Unless new protocol vulnerabilities emerge

----
### 1.4   **File Version Control** (Anjani Monica Sai Allada)

 
<img width="1108" alt="image" src="https://github.com/user-attachments/assets/e03d1cc9-68fe-4787-b6d0-ff870a9b9006">


**Assessment:**  

The assurance case focuses on ensuring that the file version control system maintains file integrity, prevents unauthorized access, and ensures that proper version history is recorded. These claims pertain to the critical properties of security within a file version control system, which are essential for safeguarding against unauthorized file modifications and ensuring reliable access to previous versions.


**Supporting Arguments:**

1. **Sub-Claim (C1):** File Integrity is Maintained Across Versions.  
   This claim asserts that file integrity is ensured as the system tracks and logs changes to files.

   **Evidence:** System logs confirming file version integrity.
   Logs provide a comprehensive trail of file changes, ensuring that any unauthorized or accidental changes are detectable.

2. **Sub-Claim (C2):** Version History is Stored Correctly
   Proper versioning and access controls prevent any misrepresentation or loss of the file history.

   **Evidence:** Version history audit reports.
   These reports validate the accuracy and completeness of the file version history.

3. **Sub-Claim (C3):** Logs and Audits Ensure No Tampering
   Ensuring audit trails and logs have not been altered is critical in maintaining trust in the system.

   **Evidence:** Audit procedure compliance documents.
   Compliance documents serve as proof that the logging mechanism is trustworthy and tamper-proof.

4. **Sub-Claim (C4):** Network Connectivity Ensures Version Upload Consistency
   A stable and secure network ensures file versions are uploaded without corruption or errors.

   **Evidence:** System monitoring network logs confirming connectivity.
   Logs demonstrate the network’s reliability during uploads, ensuring no data loss occurs during version updates.

5. **Sub-Claim (C5):** User Permissions Are Validated Before Uploads
   Uploading new file versions is restricted to authorized users, ensuring security controls prevent unauthorized file changes.

   **Evidence:** System checks validating user permissions.
   Permissions systems and checks prevent unauthorized users from altering or uploading versions.

----
### 1.5 Data Synchronization  (Gutta Prasanthi)
<img width="1097" alt="image" src="https://github.com/user-attachments/assets/494196b9-d4c0-404d-b288-b820677ff5f3">


**Assessment:**  
The Assurance Case for secure data synchronization in Seafile demonstrates a well-structured approach to ensuring data security through encryption (TLS), authentication, and error logging. The available evidence supports key claims, such as the use of TLS for data encryption and the implementation of multi-factor authentication (MFA) to mitigate credential compromise risks. However, there are gaps in evidence, particularly in areas like regular verification of encryption updates, testing of synchronization error detection under various conditions, and user credential management processes. Addressing these gaps would further strengthen the assurance of data security and resilience against potential threats.

## Part 2: Evidence Alignment Observations

### 2.1 [Claim 1 ] :The system ensures secure synchronization of data between all Seafile clients

#### 2.1.1 Available Evidence
1. [Evidence 1] :TLS encryption protocol documentation

#### 2.1.2 Unavailable/Insufficient Evidence
1. [Missing evidence 1] :Evidence showing verification of TLS updates to avoid outdated protocols.
2. [Missing evidence 2] :User feedback logs or penetration testing results to verify secure synchronization.

### 2.2 [Claim 2 ] :Data is encrypted during transmission between clients

#### 2.2.1 Available Evidence
1. [Evidence 1] :TLS encryption protocol documentation

#### 2.2.2 Unavailable/Insufficient Evidence
1. [Missing evidence 1] :Evidence ensuring the encryption protocol is regularly updated and complies with modern standards.
2. [Missing evidence 2] :Evidence on encryption standards being sufficient to withstand known vulnerabilities.

### 2.3 [Sub-Claim 3 ] : Only authenticated users can initiate synchronization

#### 2.3.1 Available Evidence
1. [Evidence E2] :Authentication logs showing successful logins

#### 2.3.2 Unavailable/Insufficient Evidence
1. [Missing evidence 1] :Reports or verification of multi-factor authentication being mandatory for access.
2. [Missing evidence 2] :Evidence of user authentication failures and how they are managed.

### 2.4 [Sub-Claim 4 ] : The system detects and logs synchronization errors in real-time

#### 2.4.1 Available Evidence
1. [Evidence E3] : Error monitoring logs during synchronization

#### 2.4.2 Unavailable/Insufficient Evidence
1. [Missing evidence 1] : Testing reports on real-time detection of synchronization errors under stress.
2. [Missing evidence 2] : Reports on how error logs help in debugging synchronization issues.

### 2.5 [Sub-Claim 5 ] : User credentials are securely stored

#### 2.5.1 Available Evidence
1. [Evidence E4] :Hashed and salted passwords stored in the database

#### 2.5.2 Unavailable/Insufficient Evidence
1. [Missing evidence 1] :Evidence on frequency and process of password rehashing.
2. [Missing evidence 2] :Evidence on how compromised accounts are managed and notified.

### 2.6 [Sub-Claim 6 ] : The system implements MFA to mitigate credential compromise risks

#### 2.6.1 Available Evidence
1. [Evidence E5] :MFA logs showing successful MFA authentication

#### 2.6.2 Unavailable/Insufficient Evidence
1. [Missing evidence 1] :Verification of MFA setup across all user accounts and clients.
2. [Missing evidence 2] :Reports on how MFA failures are handled and logged.

----
### 2.3 File Upload/Download Security

2.3.1 Available Evidence

1. Role-Based Access Control (RBAC):
   Seafile implements RBAC to manage user privileges for file operations. This is evident in the system's ability to control access based on user roles.

2. Multi-Factor Authentication (MFA):
   Logs of multi-factor authentication demonstrate the implementation of this additional security layer for user access.

3. SSL/TLS Implementation:
   Documentation and implementation of SSL/TLS protocols for secure file transfers are available, showing how data is protected during transmission.

4. AES-256 Encryption:
   Evidence of AES-256 encryption implementation for file content protection is present in Seafile's documentation.

5. File Validation Process:
   Documentation detailing the file validation process, which helps maintain file integrity during uploads and downloads.

6. Version Control Logs:
   Seafile's version control system logs provide evidence of file integrity maintenance and change tracking.

2.3.2 Unavailable/Insufficient Evidence

1. Comprehensive Security Audit Logs:
   While basic logging is implemented, there may be a lack of detailed security audit logs that track all file operations and access attempts comprehensively.

2. Third-Party Security Assessment:
   There's no evidence of recent third-party security assessments or penetration testing specifically for the file upload/download functionality.

----

### 2.4 File Version Control

#### 2.4.1 Available Evidence

1. **Version Control Logs**: Logs from the Seafile version control system provide evidence of tracking file versions, recording changes made and by whom, ensuring accountability and traceability.
2. **Audit Logs**: Seafile’s audit logs detail versioning events, showing file updates, modifications, and deletions, helping ensure file integrity across versions.
3. **File Integrity Validation**: Documentation confirms the process of file validation during versioning to maintain consistency and detect tampering or corruption during upload.
4. **Encryption of File Versions**: AES-256 encryption is used to secure each version of the file, ensuring data protection and integrity during version control operations.
5. **Access Control for Versioning**: Role-based access control (RBAC) ensures that only authorized users can modify or access specific file versions, providing an additional security layer.

#### 2.4.2 Unavailable/Insufficient Evidence

1. **Detailed Comparison Between File Versions**: While version control logs exist, there may be insufficient evidence showing detailed comparisons between versions, such as exact content changes.
2. **Third-Party Security Audit**: There is no evidence of third-party security reviews or penetration testing specific to the version control process, which could identify potential vulnerabilities in version management.

----
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

* Proactive Issue Management: We've begun raising new issues on GitHub, enhancing our project tracking and problem-solving efficiency.
* Enhanced Communication: Utilization of WhatsApp for quick updates and regular Zoom meetings has significantly improved team coordination.
* Comprehensive Research: Thorough examination of previous class work and Seafile documentation to deepen our understanding of the project.
* Effective Task Distribution: Clear assignment of responsibilities among team members, leading to more focused and productive work.
* Continuous Integration: Regular commits and updates to our project repository, maintaining an up-to-date codebase.

### Areas for Improvement

* Timely Deliverables: We need to work on submitting all parts of our assignments by agreed-upon internal deadlines.
* Collaborative Problem-Solving: Enhance our approach to jointly tackling complex issues, leveraging each team member's strengths.
* Documentation Quality: Improve the consistency and detail in our documentation, especially for complex security concepts.
* Code Review Process: Implement a more structured peer review system for our documentation contributions.


The Project Board can be found here: [Debug-Squad-Seafile](https://github.com/users/gprasanthi9/projects/3/views/1)
