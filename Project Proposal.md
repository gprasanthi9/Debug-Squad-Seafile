# Open-source Project Proposal

**Group Name:** Debug Squad Seafile

**Group Members:** Olukunle Amoo, Sreean Rikkala, Erik Weinmeister, Anjani Monica, Prasanthi Gutta


## Table of Contents

1. [Introduction](#introduction)
2. [Operational Environment](#operational-environment)
3. [Systems Engineering View Diagram](#systems-engineering-view-diagram)
4. [Perceived Threats](#perceived-threats)
5. [Security Features in Seafile](#security-features-in-seafile)
6. [Team Motivation](#team-motivation)
7. [Open-source Project Description](#open-source-project-description)
8. [License and Contribution Procedure](#license-and-contribution-procedure)
9. [Security-related History](#security-related-history)
10. [Teamwork Reflection](#teamwork-reflection)


## Introduction


**Open-source Software Project:** Seafile
      
### Operational Environment
The operational environment for Seafile is a large university research department that includes around 500 researchers and 50 administrative staff members. The department deals with several terabytes of data, including research documents and collaborative projects. The key use cases for Seafile in this setting include secure file sharing for sensitive data, collaboration on research projects with real-time file syncing and version control, and ensuring that critical research data is regularly backed up and accessible from off-campus through secure remote access. The department requires strict access control, end-to-end encryption, robust authentication (integrating with the university's single sign-on system), and comprehensive audit logging to ensure research integrity and meet compliance standards.
     
#### Systems Engineering View Diagram 
<img width="826" alt="image" src="https://github.com/user-attachments/assets/4daa7768-7fcb-4480-a371-bc29d97a0ba3">

## Perceived Threats

1. **Data breaches** exposing confidential information
2. **Man-in-the-middle attacks** during data transfer
3. **Insider threats** from privileged users
4. **Ransomware attacks** encrypting research data
5. **Data loss** due to hardware failure or human error
6. **Compliance violations** leading to loss of funding or legal issues
7. **Account hijacking** through credential theft
8. **Denial of Service (DoS) attacks** disrupting file access
9. **Data residency violations** for international collaborations


### Security Features in Seafile

### 1. Access Security
#### 1.1. Two-Factor Authentication (2FA)
- Adds an extra layer of security for user authentication
- Requires a second verification step beyond passwords

#### 1.2. Fine-Grained Access Controls
- Provides detailed control over file access, modification, and sharing
- Allows for role-based access control (RBAC)

### 2. Data Protection
#### 2.1. End-to-End Encryption
- Encrypts files before upload for secure storage
- Maintains encryption during file transfer

#### 2.2. SSL/TLS Encryption
- Secures data transmissions between users and servers
- Protects against eavesdropping and man-in-the-middle attacks

### 3. Sharing and Collaboration Security
#### 3.1. Secure Sharing Links
- Implements password protection for shared files
- Allows setting of expiration dates for shared links

#### 3.2. Collaboration Controls
- Enables granular permissions for shared workspaces
- Provides version control and change tracking for collaborative work

### 4. Monitoring and Compliance
#### 4.1. Audit Logging
- Tracks all actions related to file access and modifications
- Generates detailed reports for compliance and security analysis

### 5. Infrastructure Security
#### 5.1. Secure Data Centers
- Utilizes physically secure and geographically distributed data centers
- Implements redundancy and disaster recovery measures


## Team Motivation

Our team selected Seafile for its robust combination of open-source flexibility and strong security features, which align well with the demands of academic and research environments. The open-source nature of Seafile allows for customization to meet specific institutional needs, while its emphasis on security addresses the critical requirement of protecting sensitive research data.
Seafile's scalability was a key factor in our decision, as it can efficiently manage the increasing volumes of data typical in research settings. The project's active development community ensures ongoing improvements and support, which is crucial for maintaining a secure and up-to-date system.
We recognized the potential for significant impact, given Seafile's widespread use in academic institutions. Its ability to integrate with existing IT infrastructure in universities makes it a pragmatic choice for real-world implementation. This project offers our team the opportunity to gain valuable experience with a production-grade file sharing and collaboration platform, enhancing our skills in relevant technologies and development practices.
On a personal level, we saw this as an incredible learning opportunity. Getting hands-on experience with a robust file sharing and collaboration platform will be invaluable for our future careers. We're not just studying theory here – we're working with real-world tools used by organizations globally. It's challenging, sure, but that's what makes it exciting. We're eager to dive in, learn as much as we can, and hopefully make a meaningful contribution to the project along the way



## Open-source Project Description
#### What is it?
Seafile is a file synching and sharing service running on Linux.  It uses a web frontend with Nginx/Apache backend.  MySQL is the supported database.  There is a docker deployment to reduce the time to deploy and configuration options.
For managing authorizations and access and LDAP/AD connection is utilized, which can also leverage Single Sign On


#### Contributors 
https://forum.seafile.com 



#### Languages
Seahub is written in Django with the server being seaf-server.

#### Platform
Nginx/Apache backend with a web browser or mobile app for the frontend

#### Documentation Sources
Seafile Admin Manual https://manual.seafile.com/


## License and Contribution Procedure
#### Licenses
Seafile iOS client: Apache License v2
Seafile Android client: GPLv3
Desktop syncing client (this repository): GPLv2
Seafile Server core: AGPLv3
Seahub (Seafile server Web UI): Apache License v2	



#### Contribution Procedure
The Seafile community forum is location to check about developing and adding to the project Seafile Community Forum https://forum.seafile.com/t/welcome-to-seafile-community-forum/8/2

#### Contributor Agreements
The Seafile community forum is location to check about developing and adding to the project Seafile Community Forum https://forum.seafile.com/t/welcome-to-seafile-community-forum/8/2


## Security-related History

Seafile has implemented various security improvements over time:

- Server-side encryption for data at rest.
- Two-factor authentication (2FA) for enhanced user security.
- Improved password-protected sharing links with expiration dates.
- LDAP integration security enhancements.
- Stricter password policies to reduce account breaches.
- Continuous updates and security patches.

**Recent Updates**:
- Added detailed audit logging for better compliance tracking.
- Improved virtual file support for safer sync&#8203;:contentReference[oaicite:0]{index=0}.
- Docker-related fixes, especially for OnlyOffice compatibility&#8203;:contentReference[oaicite:1]{index=1}.

[Seafile Security Advisory](https://www.seafile.com/en/security/)



## Teamwork Reflection

Our team has worked cohesively, proactively coordinating meetings to select an open-source project that suited everyone’s schedules. We established a regular meeting time, with members willing to hold additional sessions to ensure we met our deadlines. Each member has contributed uniquely, offering ideas and engaging in thoughtful discussions, weighing the pros and cons of potential projects.
As team lead, Kunle consistently communicated with Dr. Gandhi to arrange meetings when necessary, coordinated group tasks, and ensured prompt contributions from every member. Prasanthi set up the GitHub repository and typed the hypothetical operational environment, Monica designed the Systems Engineering View diagram and security features, Sreean documented the perceived threat and security related history, while Erik outlined the open source project description and license and contribution procedure. Kunle also took responsibility for the reflection, team motivation.
The primary challenge we faced as a team was selecting an open-source project that aligned with the course standards before our initial meeting with Dr. Gandhi. After some adjustments, we chose Seafile as our focus. Since then, we’ve successfully established a communication channel on WhatsApp and are tracking individual tasks and issues within the GitHub project. Our collaborative work on this markdown paper began in a shared Google Doc, which has allowed for smooth initial contributions from all team members.
