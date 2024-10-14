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



### 1.4 **File Version Control** (Anjani Monica Sai Allada)
 
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

---

### 2.2 [Claim 2 Name]

#### 2.2.1 Available Evidence
1. [Evidence 1]
2. [Evidence 2]

#### 2.2.2 Unavailable/Insufficient Evidence
1. [Missing evidence 1]
2. [Missing evidence 2]

---

### 2.3 File Upload/Download Security (Sreean Rikkala)

#### 2.3.1 Available Evidence
1. [Evidence 1]
2. [Evidence 2]

#### 2.3.2 Unavailable/Insufficient Evidence
1. [Missing evidence 1]
2. [Missing evidence 2]

---

### 2.4 [Claim 4 Name]

#### 2.4.1 Available Evidence
1. [Evidence 1]
2. [Evidence 2]

#### 2.4.2 Unavailable/Insufficient Evidence
1. [Missing evidence 1]
2. [Missing evidence 2]

---

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
