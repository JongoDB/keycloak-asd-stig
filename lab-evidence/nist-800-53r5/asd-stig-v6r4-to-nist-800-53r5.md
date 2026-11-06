# ASD STIG V6R4 -> NIST SP 800-53 Rev 5 crosswalk

Sources: DISA U_CCI_List.xml version 2025-01-23; Electronic (OSCAL) Version of NIST SP 800-53 Rev 5.2.0 Controls and SP 800-53A Rev 5.2.0 Assessment Procedures 5.2.0; NIST SP 800-53B Rev 5 OSCAL profiles (LOW/MODERATE/HIGH). Mapping chain: ASD rule -> CCI (DISA) -> 800-53 Rev 5 control. Status source: labapp-asd-stig-results.json.
All controls referenced by ASD rules.

| Control rollup | Controls |
|---|---|
| Outside the IdP (app/platform/process) | 73 |
| Partial - IdP part done | 44 |
| Satisfied (IdP) | 19 |

Rollup rules: **Satisfied (IdP)** = every mapped ASD rule is Not a Finding/N/A in the run; **Partial** = the Keycloak part passed but app/platform/process rules under the same control remain; **Open** = at least one mapped rule failed; **Outside the IdP** = only app/platform/process rules map here. A control is only fully implemented when the system's other components (apps, platform, procedures) cover their rules too.

| Control | Title | Family | Baselines | Rollup | ASD rules (status) |
|---|---|---|---|---|---|
| AC-2 | Account Management | Access Control | L/M/H | Outside the IdP (app/platform/process) | V-222619(NR) |
| AC-2(1) | Automated System Account Management | Access Control | M/H | Satisfied (IdP) | V-222407(NaF), V-222417(NaF), V-222418(NaF), V-222419(NaF), V-222420(NaF), V-222422(NaF) |
| AC-2(2) | Automated Temporary and Emergency Account Management | Access Control | M/H | Satisfied (IdP) | V-222409(NaF) |
| AC-2(3) | Disable Accounts | Access Control | M/H | Partial - IdP part done | V-222411(NaF), V-222412(IdP done), V-222535(NR) |
| AC-2(4) | Automated Audit Actions | Access Control | M/H | Satisfied (IdP) | V-222413(NaF), V-222414(NaF), V-222415(NaF), V-222416(NaF), V-222421(NaF) |
| AC-3 | Access Enforcement | Access Control | L/M/H | Partial - IdP part done | V-222425(IdP done) |
| AC-3(4) | Discretionary Access Control | Access Control | - | Outside the IdP (app/platform/process) | V-222426(NR) |
| AC-4 | Information Flow Enforcement | Access Control | M/H | Outside the IdP (app/platform/process) | V-222427(NR), V-222428(NR) |
| AC-6(10) | Prohibit Non-privileged Users from Executing Privileged Functions | Access Control | M/H | Partial - IdP part done | V-222429(IdP done) |
| AC-6(4) | Separate Processing Domains | Access Control | - | Outside the IdP (app/platform/process) | V-222620(NR) |
| AC-6(8) | Privilege Levels for Code Execution | Access Control | - | Partial - IdP part done | V-222430(IdP done) |
| AC-6(9) | Log Use of Privileged Functions | Access Control | M/H | Satisfied (IdP) | V-222431(NaF) |
| AC-7 | Unsuccessful Logon Attempts | Access Control | L/M/H | Partial - IdP part done | V-222432(NaF), V-222433(IdP done) |
| AC-8 | System Use Notification | Access Control | L/M/H | Satisfied (IdP) | V-222434(NaF), V-222435(NaF), V-222436(NaF) |
| AC-9 | Previous Logon Notification | Access Control | - | Partial - IdP part done | V-222437(IdP done) |
| AC-10 | Concurrent Session Control | Access Control | H | Satisfied (IdP) | V-222387(NaF) |
| AC-12 | Session Termination | Access Control | M/H | Partial - IdP part done | V-222388(IdP done), V-222389(IdP done), V-222390(IdP done) |
| AC-12(1) | User-initiated Logouts | Access Control | - | Partial - IdP part done | V-222391(IdP done) |
| AC-12(2) | Termination Message | Access Control | - | Outside the IdP (app/platform/process) | V-222392(NR) |
| AC-16 | Security and Privacy Attributes | Access Control | - | Outside the IdP (app/platform/process) | V-222393(NR), V-222394(NR), V-222395(NR) |
| AC-17(2) | Protection of Confidentiality and Integrity Using Encryption | Access Control | M/H | Partial - IdP part done | V-222396(IdP done), V-222397(IdP done), V-222398(NR), V-222399(NR), V-222400(NaF), V-222401(NaF), V-222402(NaF), V-222403(NaF), V-222404(NaF), V-222405(NaF), V-222406(NaF) |
| AC-23 | Data Mining Protection | Access Control | - | Outside the IdP (app/platform/process) | V-222423(NR), V-222424(NR) |
| AT-3(3) | Practical Exercises | Awareness and Training | - | Outside the IdP (app/platform/process) | V-222673(NR) |
| AU-3 | Content of Audit Records | Audit and Accountability | L/M/H | Partial - IdP part done | V-222469(IdP done), V-222470(IdP done), V-222471(NR), V-222472(NR), V-222473(NaF), V-222474(NaF), V-222475(IdP done), V-222476(NaF), V-222477(NaF) |
| AU-3(1) | Additional Audit Information | Audit and Accountability | M/H | Partial - IdP part done | V-222478(NaF), V-222479(NR) |
| AU-4(1) | Transfer to Alternate Storage | Audit and Accountability | - | Partial - IdP part done | V-222481(IdP done), V-222482(IdP done) |
| AU-5 | Response to Audit Logging Process Failures | Audit and Accountability | L/M/H | Outside the IdP (app/platform/process) | V-222485(NR), V-222486(NR) |
| AU-5(1) | Storage Capacity Warning | Audit and Accountability | H | Outside the IdP (app/platform/process) | V-222483(NR) |
| AU-5(2) | Real-time Alerts | Audit and Accountability | H | Outside the IdP (app/platform/process) | V-222484(NR) |
| AU-6 | Audit Record Review, Analysis, and Reporting | Audit and Accountability | L/M/H | Outside the IdP (app/platform/process) | V-222623(NR) |
| AU-6(10) [Rev4 only] | (withdrawn/incorporated in Rev 5) | ? | - | Outside the IdP (app/platform/process) | V-222622(NR) |
| AU-6(4) | Central Review and Analysis | Audit and Accountability | - | Partial - IdP part done | V-222480(IdP done), V-222487(IdP done) |
| AU-7 | Audit Record Reduction and Report Generation | Audit and Accountability | M/H | Partial - IdP part done | V-222489(IdP done), V-222490(IdP done), V-222491(IdP done), V-222492(IdP done), V-222493(IdP done), V-222494(IdP done), V-222495(IdP done), V-222496(IdP done) |
| AU-7(1) | Automatic Processing | Audit and Accountability | M/H | Partial - IdP part done | V-222488(IdP done) |
| AU-8 | Time Stamps | Audit and Accountability | L/M/H | Partial - IdP part done | V-222497(IdP done), V-222498(IdP done), V-222499(IdP done) |
| AU-9 | Protection of Audit Information | Audit and Accountability | L/M/H | Partial - IdP part done | V-222500(IdP done), V-222501(IdP done), V-222502(IdP done), V-222503(NR), V-222504(NR), V-222505(NR) |
| AU-9(2) | Store on Separate Physical Systems or Components | Audit and Accountability | H | Outside the IdP (app/platform/process) | V-222506(NR) |
| AU-9(3) | Cryptographic Protection | Audit and Accountability | H | Outside the IdP (app/platform/process) | V-222507(NR), V-222508(NR), V-222509(NR) |
| AU-10 | Non-repudiation | Audit and Accountability | H | Outside the IdP (app/platform/process) | V-222438(NR) |
| AU-11 | Audit Record Retention | Audit and Accountability | L/M/H | Outside the IdP (app/platform/process) | V-222621(NR) |
| AU-12 | Audit Record Generation | Audit and Accountability | L/M/H | Partial - IdP part done | V-222441(IdP done), V-222442(IdP done), V-222443(IdP done), V-222444(NaF), V-222445(IdP done), V-222446(NaF), V-222447(IdP done), V-222448(NaF), V-222449(NaF), V-222450(NaF), V-222451(NaF), V-222452(NR), V-222453(NR), V-222454(NaF), V-222455(NaF), V-222456(NR), V-222457(NR), V-222458(NaF), V-222459(NR), V-222460(NaF), V-222461(NR), V-222462(NaF), V-222463(NaF), V-222464(NaF), V-222465(NR), V-222466(NaF), V-222467(NaF), V-222672(NaF) |
| AU-12(1) | System-wide and Time-correlated Audit Trail | Audit and Accountability | H | Outside the IdP (app/platform/process) | V-222439(NR) |
| AU-14(1) | System Start-up | Audit and Accountability | - | Satisfied (IdP) | V-222468(NaF) |
| CA-2(2) | Specialized Assessments | Assessment, Authorization, and Monitoring | H | Outside the IdP (app/platform/process) | V-222624(NR) |
| CM-4(2) | Verification of Controls | Configuration Management | M/H | Outside the IdP (app/platform/process) | V-222625(NR) |
| CM-5 | Access Restrictions for Change | Configuration Management | L/M/H | Outside the IdP (app/platform/process) | V-222626(NR) |
| CM-5(1) | Automated Access Enforcement and Audit Records | Configuration Management | H | Satisfied (IdP) | V-222511(NaF), V-222512(NaF) |
| CM-5(6) | Limit Library Privileges | Configuration Management | - | Outside the IdP (app/platform/process) | V-222514(NR) |
| CM-6 | Configuration Settings | Configuration Management | L/M/H | Partial - IdP part done | V-222410(IdP done), V-222515(NR), V-222547(NaF), V-222567(NR) |
| CM-6 [Rev4 only] | Configuration Settings | Configuration Management | L/M/H | Outside the IdP (app/platform/process) | V-222627(NR) |
| CM-7 | Least Functionality | Configuration Management | L/M/H | Partial - IdP part done | V-222518(NaF), V-222519(IdP done) |
| CM-7(2) | Prevent Program Execution | Configuration Management | M/H | Outside the IdP (app/platform/process) | V-222516(NR) |
| CM-7(3) | Registration Compliance | Configuration Management | - | Outside the IdP (app/platform/process) | V-222628(NR), V-222629(NR) |
| CM-7(5) | Authorized Software — Allow-by-exception | Configuration Management | M/H | Outside the IdP (app/platform/process) | V-222517(NR) |
| CM-9 | Configuration Management Plan | Configuration Management | M/H | Outside the IdP (app/platform/process) | V-222630(NR), V-222631(NR), V-222632(NR), V-222633(NR) |
| CM-11(2) | Software Installation with Privileged Status | Configuration Management | - | Outside the IdP (app/platform/process) | V-222510(NR) |
| CM-14 | Signed Components | Configuration Management | - | Outside the IdP (app/platform/process) | V-222513(NR) |
| CP-2 | Contingency Plan | Contingency Planning | L/M/H | Outside the IdP (app/platform/process) | V-222636(NR), V-222637(NR) |
| CP-2(8) | Identify Critical Assets | Contingency Planning | M/H | Outside the IdP (app/platform/process) | V-222635(NR) |
| CP-9 | System Backup | Contingency Planning | L/M/H | Outside the IdP (app/platform/process) | V-222638(NR) |
| CP-9 [Rev4 only] | System Backup | Contingency Planning | L/M/H | Outside the IdP (app/platform/process) | V-222639(NR), V-222640(NR) |
| CP-11 | Alternate Communications Protocols | Contingency Planning | - | Outside the IdP (app/platform/process) | V-222634(NR) |
| IA-2 | Identification and Authentication (Organizational Users) | Identification and Authentication | L/M/H | Satisfied (IdP) | V-222522(NaF) |
| IA-2(1) | Multi-factor Authentication to Privileged Accounts | Identification and Authentication | L/M/H | Partial - IdP part done | V-222523(IdP done), V-222527(IdP done) |
| IA-2(12) | Acceptance of PIV Credentials | Identification and Authentication | L/M/H | Satisfied (IdP) | V-222524(NaF), V-222525(NaF) |
| IA-2(2) | Multi-factor Authentication to Non-privileged Accounts | Identification and Authentication | L/M/H | Partial - IdP part done | V-222526(NaF), V-222528(IdP done) |
| IA-2(5) | Individual Authentication with Group Authentication | Identification and Authentication | H | Outside the IdP (app/platform/process) | V-222408(NR), V-222529(NR) |
| IA-2(8) | Access to Accounts — Replay Resistant | Identification and Authentication | L/M/H | Satisfied (IdP) | V-222530(NaF), V-222531(NaF) |
| IA-3 | Device Identification and Authentication | Identification and Authentication | M/H | Partial - IdP part done | V-222532(IdP done), V-222533(IdP done) |
| IA-3(1) | Cryptographic Bidirectional Authentication | Identification and Authentication | - | Outside the IdP (app/platform/process) | V-222534(NR) |
| IA-5 | Authenticator Management | Identification and Authentication | L/M/H | Satisfied (IdP) | V-222548(NaF) |
| IA-5(1) | Password-based Authentication | Identification and Authentication | L/M/H | Partial - IdP part done | V-222536(NaF), V-222537(NaF), V-222538(NaF), V-222539(NaF), V-222540(NaF), V-222541(IdP done), V-222542(NaF), V-222543(NaF), V-222544(NaF), V-222545(NaF), V-222546(NaF) |
| IA-5(13) | Expiration of Cached Authenticators | Identification and Authentication | - | Satisfied (IdP) | V-222549(NaF) |
| IA-5(2) | Public Key-based Authentication | Identification and Authentication | M/H | Partial - IdP part done | V-222550(NaF), V-222551(NR), V-222552(NaF), V-222553(IdP done) |
| IA-5(6) | Protection of Authenticators | Identification and Authentication | M/H | Satisfied (IdP) | V-222641(NaF) |
| IA-5(7) [Rev4 only] | (withdrawn/incorporated in Rev 5) | ? | - | Outside the IdP (app/platform/process) | V-222642(NR) |
| IA-6 | Authentication Feedback | Identification and Authentication | L/M/H | Satisfied (IdP) | V-222554(NaF) |
| IA-7 | Cryptographic Module Authentication | Identification and Authentication | L/M/H | Partial - IdP part done | V-222555(IdP done) |
| IA-8 | Identification and Authentication (Non-organizational Users) | Identification and Authentication | L/M/H | Satisfied (IdP) | V-222556(NaF) |
| IA-8(1) | Acceptance of PIV Credentials from Other Agencies | Identification and Authentication | L/M/H | Partial - IdP part done | V-222557(IdP done), V-222558(IdP done) |
| IA-8(2) | Acceptance of External Authenticators | Identification and Authentication | L/M/H | Outside the IdP (app/platform/process) | V-222559(NR) |
| IA-8(4) | Use of Defined Profiles | Identification and Authentication | L/M/H | Outside the IdP (app/platform/process) | V-222560(NR) |
| IA-11 | Re-authentication | Identification and Authentication | L/M/H | Partial - IdP part done | V-222521(IdP done) |
| MA-4 | Nonlocal Maintenance | Maintenance | L/M/H | Partial - IdP part done | V-222565(IdP done), V-222566(IdP done) |
| MA-4(1) | Logging and Review | Maintenance | - | Satisfied (IdP) | V-222561(NaF) |
| MA-4(6) | Cryptographic Protection | Maintenance | - | Partial - IdP part done | V-222562(IdP done), V-222563(IdP done) |
| MA-4(7) | Disconnect Verification | Maintenance | - | Outside the IdP (app/platform/process) | V-222564(NR) |
| MP-3 | Media Marking | Media Protection | M/H | Outside the IdP (app/platform/process) | V-222643(NR) |
| PM-14 | Testing, Training, and Monitoring | Program Management | - | Outside the IdP (app/platform/process) | V-222644(NR) |
| SA-4(5) | System, Component, and Service Configurations | System and Services Acquisition | H | Satisfied (IdP) | V-222661(NaF), V-222662(NaF) |
| SA-5 | System Documentation | System and Services Acquisition | L/M/H | Outside the IdP (app/platform/process) | V-222663(NR), V-222664(NR) |
| SA-10 | Developer Configuration Management | System and Services Acquisition | M/H | Outside the IdP (app/platform/process) | V-222650(NR) |
| SA-10(1) | Software and Firmware Integrity Verification | System and Services Acquisition | - | Outside the IdP (app/platform/process) | V-222645(NR) |
| SA-11 | Developer Testing and Evaluation | System and Services Acquisition | M/H | Outside the IdP (app/platform/process) | V-222651(NR), V-222652(NR) |
| SA-11(2) | Threat Modeling and Vulnerability Analyses | System and Services Acquisition | - | Outside the IdP (app/platform/process) | V-222646(NR), V-222647(NR) |
| SA-11(4) | Manual Code Reviews | System and Services Acquisition | - | Outside the IdP (app/platform/process) | V-222648(NR), V-222649(NR) |
| SA-15 | Development Process, Standards, and Tools | System and Services Acquisition | M/H | Outside the IdP (app/platform/process) | V-222653(NR), V-222654(NR) |
| SA-15(10) | Incident Response Plan | System and Services Acquisition | - | Outside the IdP (app/platform/process) | V-222657(NR) |
| SA-15(4) [Rev4 only] | (withdrawn/incorporated in Rev 5) | ? | - | Outside the IdP (app/platform/process) | V-222655(NR) |
| SA-15(5) | Attack Surface Reduction | System and Services Acquisition | - | Outside the IdP (app/platform/process) | V-222656(NR) |
| SA-22 | Unsupported System Components | System and Services Acquisition | L/M/H | Outside the IdP (app/platform/process) | V-222658(NR), V-222659(NR) |
| SA-22 [Rev4 only] | Unsupported System Components | System and Services Acquisition | L/M/H | Outside the IdP (app/platform/process) | V-222660(NR) |
| SC-2 | Separation of System and User Functionality | System and Communications Protection | M/H | Partial - IdP part done | V-222574(IdP done) |
| SC-3 | Security Function Isolation | System and Communications Protection | H | Outside the IdP (app/platform/process) | V-222590(NR) |
| SC-4 | Information in Shared System Resources | System and Communications Protection | M/H | Outside the IdP (app/platform/process) | V-222592(NR) |
| SC-5 | Denial-of-service Protection | System and Communications Protection | L/M/H | Outside the IdP (app/platform/process) | V-222593(NR) |
| SC-5 [Rev4 only] | Denial-of-service Protection | System and Communications Protection | L/M/H | Partial - IdP part done | V-222667(IdP done) |
| SC-5(1) | Restrict Ability to Attack Other Systems | System and Communications Protection | - | Partial - IdP part done | V-222594(IdP done) |
| SC-5(2) | Capacity, Bandwidth, and Redundancy | System and Communications Protection | - | Outside the IdP (app/platform/process) | V-222595(NR) |
| SC-7(13) | Isolation of Security Tools, Mechanisms, and Support Components | System and Communications Protection | - | Outside the IdP (app/platform/process) | V-222671(NR) |
| SC-8 | Transmission Confidentiality and Integrity | System and Communications Protection | M/H | Partial - IdP part done | V-222596(IdP done) |
| SC-8(1) | Cryptographic Protection | System and Communications Protection | M/H | Partial - IdP part done | V-222597(IdP done) |
| SC-8(2) | Pre- and Post-transmission Handling | System and Communications Protection | - | Partial - IdP part done | V-222598(IdP done), V-222599(IdP done), V-222600(IdP done), V-222601(NR) |
| SC-10 | Network Disconnect | System and Communications Protection | M/H | Partial - IdP part done | V-222568(IdP done) |
| SC-11 | Trusted Path | System and Communications Protection | - | Satisfied (IdP) | V-222520(NaF) |
| SC-13 | Cryptographic Protection | System and Communications Protection | L/M/H | Partial - IdP part done | V-222570(IdP done), V-222571(IdP done), V-222572(IdP done), V-222573(IdP done), V-265634(NR) |
| SC-18(1) | Identify Unacceptable Code and Take Corrective Actions | System and Communications Protection | - | Outside the IdP (app/platform/process) | V-222618(NR) |
| SC-18(2) | Acquisition, Development, and Use | System and Communications Protection | - | Outside the IdP (app/platform/process) | V-222665(NR) |
| SC-23 | Session Authenticity | System and Communications Protection | M/H | Partial - IdP part done | V-222575(IdP done), V-222576(IdP done), V-222577(NaF) |
| SC-23(1) | Invalidate Session Identifiers at Logout | System and Communications Protection | - | Partial - IdP part done | V-222578(IdP done) |
| SC-23(3) | Unique System-generated Session Identifiers | System and Communications Protection | - | Partial - IdP part done | V-222579(NaF), V-222580(NaF), V-222581(NaF), V-222582(NaF), V-222583(IdP done) |
| SC-23(5) | Allowed Certificate Authorities | System and Communications Protection | - | Outside the IdP (app/platform/process) | V-222584(NR) |
| SC-24 | Fail in Known State | System and Communications Protection | H | Partial - IdP part done | V-222585(NaF), V-222586(NR) |
| SC-28 | Protection of Information at Rest | System and Communications Protection | M/H | Outside the IdP (app/platform/process) | V-222587(NR) |
| SC-28(1) | Cryptographic Protection | System and Communications Protection | M/H | Outside the IdP (app/platform/process) | V-222588(NR), V-222589(NR) |
| SC-28(2) | Offline Storage | System and Communications Protection | - | Outside the IdP (app/platform/process) | V-222666(NR) |
| SC-39 | Process Isolation | System and Communications Protection | L/M/H | Outside the IdP (app/platform/process) | V-222591(NR) |
| SI-2 | Flaw Remediation | System and Information Integrity | L/M/H | Outside the IdP (app/platform/process) | V-222614(NR) |
| SI-2(6) | Removal of Previous Versions of Software and Firmware | System and Information Integrity | - | Outside the IdP (app/platform/process) | V-222613(NR) |
| SI-4(12) | Automated Organization-generated Alerts | System and Information Integrity | H | Outside the IdP (app/platform/process) | V-222668(NR) |
| SI-5 | Security Alerts, Advisories, and Directives | System and Information Integrity | L/M/H | Outside the IdP (app/platform/process) | V-222669(NR), V-222670(NR) |
| SI-6 | Security and Privacy Function Verification | System and Information Integrity | H | Outside the IdP (app/platform/process) | V-222615(NR), V-222616(NR), V-222617(NR) |
| SI-10 | Information Input Validation | System and Information Integrity | M/H | Partial - IdP part done | V-222602(IdP done), V-222603(IdP done), V-222604(NR), V-222605(NR), V-222606(NR), V-222607(NR), V-222608(NR) |
| SI-10(3) | Predictable Behavior | System and Information Integrity | - | Outside the IdP (app/platform/process) | V-222609(NR) |
| SI-11 | Error Handling | System and Information Integrity | M/H | Partial - IdP part done | V-222610(IdP done), V-222611(IdP done) |
| SI-16 | Memory Protection | System and Information Integrity | M/H | Outside the IdP (app/platform/process) | V-222612(NR) |

CSV with one row per control x CCI x rule (owner, status, Keycloak implementation, remaining action, evidence): `asd-stig-v6r4-to-nist-800-53r5.csv`.
Rev 5 note: controls marked [Rev4 only] have no Rev 5 reference in the DISA CCI list (withdrawn or incorporated into other Rev 5 controls); map them per NIST's Rev 4->Rev 5 analysis when you build the SSP.
