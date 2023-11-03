# Cytrac MITRE Top 10 Test agent
TOP 10 Adversarial Technique Test Agent

**Doesn't contain any real malware, read Usage paragraph. The extracted executable is safe to allow in Antivirus settings. To fully utilze the agent, all of the dependecies (Mimikatz, Sharphound/Bloodhound...) must be allowed by the antivirus to allow SIEM/EDR/XDR rules to trigger.**

**The ZIP archive password is: PASSWORD**

## Description

# 1.1.	Purpose

The modern threat landscape demands robust security measures, and the validation of Security Operations Center (SOC) and IT security services/products is crucial to ensure the readiness of organizations to defend against adversarial attacks. This paper introduces the TOP 10 Adversarial Technique Test Agent, a testing tool designed to evaluate the efficacy of SOC and IT security solutions on Windows systems. The tool assesses the detection and prevention capabilities of security systems against ten key MITRE ATT&CK techniques and sub-techniques based on Red Canaries Top techniques, providing high level insights into their ability to safeguard against real-world threats.
# 1.2.	Methodology

The paper outlines a systematic methodology for testing SOC and IT security services/products using the TOP 10 Adversarial Technique Test Agent. It covers the following MITRE techniques and sub-techniques:
-	T1059:003 - Windows Command Shell
-	T1059:001 - PowerShell
-	T1047 - Windows Management Instrumentation
-	T1027 - Obfuscated Files or Information
-	T1218.011 - Rundll32
-	T1105 - Ingress Tool Transfer
-	T1055 - Process Injection
-	T1569.002 - Service Execution
-	T1036.003 - Rename System Utilities
-	T1003.001 - LSASS Memory

# 1.3.	Findings

Through testing of the specified MITRE techniques and sub-techniques, the TOP 10 Adversarial Technique Test Agent provided critical insights into the SOC's or security product's performance. It had assessed their ability to detect, respond to, and mitigate threats posed by these adversarial techniques. The findings revealed strengths and weaknesses in the security infrastructure, enabling organizations to make informed decisions for improvement.

# 1.4.	Benefits

Enhanced Security: By identifying gaps in detection and prevention capabilities, organizations can bolster their security posture and better protect critical assets.
Cost-Efficiency: Targeted improvements based on test results can save resources and prevent potential breaches, reducing the overall cost of security operations.
Compliance Assurance: Demonstrating robust security testing and validation is essential for compliance with industry regulations and standards.
Proactive Defense: Continuous testing allow organizations to stay ahead of evolving threat landscapes.

# 1.5.	Conclusion

In an era where cyber threats are increasingly sophisticated and frequent, the TOP 10 Adversarial Technique Test Agent offers a vital tool for SOC and IT security service/product validation. By assessing security systems against specific MITRE techniques and sub-techniques, organizations can strengthen their defences, proactively respond to threats, and ultimately safeguard their digital assets and reputation. This research paper serves as a guide for organizations seeking to fortify their security posture and ensure the reliability of their SOC and security solutions in the face of emerging cyber threats.
 
# 2.	Techniques

2.1.	T1059.003 - Windows Command Shell
2.1.1.	Description
Tactic: Execution
Technique: Command and Scripting Interpreter
Sub-Technique: Windows Command Shell (cmd.exe)
Platform: Windows
2.1.2.	Attack Description
In this attack technique, adversaries leverage the built-in Windows Command Shell, which is commonly accessed via the "cmd.exe" utility. They use this shell to run arbitrary commands and scripts, allowing them to manipulate the compromised system, escalate privileges, move laterally within a network, and achieve their malicious objectives.
Scenario:
Creates and executes a simple batch script. Upon execution, CMD will briefly launch to run the batch script then close again.
2.1.3.	Detection
Detecting T1059.003 - Windows Command Shell attacks is critical for early threat mitigation. Here are some methods to detect this technique:
-	Command Line Logging: Enable and monitor Windows command-line logging (Command Prompt logs) or use Sysmon. Collect and analyse command-line usage data, looking for suspicious or unauthorized commands and arguments. Advanced analytics and anomaly detection can help identify malicious activity.
-	Behavioural Analysis: Employ behavioural analysis to detect unusual behaviour patterns associated with cmd.exe. For example, identifying cmd.exe spawning multiple child processes or executing commands that are not typical for the user or system can raise red flags.
-	Command Whitelisting/Blacklisting: Maintain a list of allowed and prohibited commands and scripts. Employ application control or whitelisting solutions to restrict the execution of unauthorized commands. This can help prevent attackers from running malicious scripts through cmd.exe.
-	Heuristic Detection: Use heuristic or signature-based detection methods to identify known malicious commands, scripting techniques, or common attack payloads executed via the Windows Command Shell.
2.1.4.	Prevention
Preventing T1059:003 attacks involve implementing security measures to minimize the risk of adversaries exploiting the Windows Command Shell:
-	Least Privilege: Apply the principle of least privilege to limit the permissions and capabilities of user accounts and processes, reducing the potential impact of any compromised cmd.exe instances.
-	Application Control: Implement application control solutions to restrict the execution of cmd.exe and other command-line interpreters only to authorized users and approved scripts.
-	Patching and Updating: Keep the operating system and software up to date to address known vulnerabilities that attackers might exploit via the command shell.
-	Security Software: Employ endpoint security solutions with intrusion detection capabilities to monitor and block suspicious cmd.exe activities in real-time.
-	User Education: Educate users about the risks associated with running unauthorized scripts and commands and encourage them to report any suspicious activity promptly.
-	Network Segmentation: Isolate critical systems and segments to limit lateral movement if an attacker gains access to cmd.exe on one system.
-	Security Monitoring: Implement continuous monitoring and incident response procedures to quickly detect and respond to cmd.exe-related threats.

By combining these detection and prevention strategies, organizations can significantly reduce the risk of adversaries successfully using T1059:003 - Windows Command Shell to compromise their systems and networks.
 
2.2.	T1059.001 – PowerShell
2.2.1.	Description
Tactic: Execution
Technique: Command and Scripting Interpreter
Sub-Technique: PowerShell
Platform: Windows
2.2.2.	Attack Description
T1059.001 focuses on adversaries using PowerShell, a powerful and versatile scripting language and framework available on Windows systems, for malicious purposes. PowerShell provides attackers with a wide range of capabilities, including executing scripts, downloading and running malware, and performing various system-level activities, all while operating under the radar.
Scenario:
Download Mimikatz and dump credentials. Upon execution, mimikatz dump details and password hashes will be displayed (only once).
2.2.3.	Detection
Detecting T1059:001 - PowerShell attacks requires vigilant monitoring and analysis of PowerShell activities. Here are some methods to detect this technique:
-	PowerShell Logging: Enable PowerShell script block logging and transcription to record the commands and scripts executed through PowerShell or install Sysmon with a proper configuration. Centralize and analyse these logs for signs of malicious activity, such as suspicious or obfuscated scripts.
-	Script Analysis: Implement script analysis tools and sandboxes that can analyze PowerShell scripts for potentially malicious behaviour, such as attempts to access sensitive data or make unauthorized system changes.
-	Behavioural Anomalies: Utilize behavioural analytics to detect unusual PowerShell behaviour, such as PowerShell sessions being initiated from unusual locations or by unusual users, or PowerShell invoking unusual system commands.
-	Command and Argument Analysis: Analyse PowerShell command-line arguments and parameters for indicators of compromise. Look for commands that are commonly used in attacks or known to be associated with malicious activity. Enable and monitor Windows command-line logging (Command Prompt logs) or use Sysmon.
-	Heuristic Detection: Employ heuristic or pattern-based detection methods to identify known malicious PowerShell scripts or command sequences.
2.2.4.	Prevention
Preventing T1059:001 attacks involve taking measures to restrict the misuse of PowerShell while still allowing legitimate use:
-	Constrained Language Mode: Enable PowerShell's Constrained Language Mode to restrict the execution of scripts to a safer subset of PowerShell commands, limiting the potential for malicious activities.
-	Execution Policy: Set PowerShell execution policies to restrict script execution. Enforce policies that allow only signed scripts to run, minimizing the risk of running untrusted scripts.
-	Application Whitelisting: Implement application control or whitelisting solutions to allow only approved PowerShell scripts and commands to run. Block execution of unknown or unauthorized scripts.
-	User Training: Educate users and administrators about the dangers of running untrusted PowerShell scripts and promote the use of safe coding practices.
-	Regular Patching: Keep PowerShell up-to-date and apply security patches to address known vulnerabilities that attackers might exploit.
-	Network Segmentation: Isolate critical systems and networks to limit lateral movement in case an attacker gains access to PowerShell.
-	Monitoring and Incident Response: Establish continuous monitoring and incident response procedures to swiftly detect and respond to suspicious PowerShell activities.

By applying these detection and prevention strategies, organizations can enhance their ability to detect and mitigate T1059:001 - PowerShell attacks, reducing the risk of unauthorized use of PowerShell for malicious purposes.
 
2.3.	T1047 - Windows Management Instrumentation
2.3.1.	Description
Tactic: Execution
Technique: Windows Management Instrumentation
Platform: Windows
2.3.2.	Attack Description
T1047 focuses on adversaries leveraging Windows Management Instrumentation (WMI), a powerful framework within Windows for managing and automating system tasks. Attackers can misuse WMI to execute arbitrary code, gather system information, and interact with various aspects of a Windows environment. WMI provides extensive capabilities, making it attractive to adversaries for conducting malicious activities.
 	Scenario:
-	An adversary might use WMI to list all local User Accounts. When the test completes , there should be local user accounts information displayed on the command line.
-	An adversary might use WMI to list Processes running on the compromised host. When the test completes , there should be running processes listed on the command line.
-	This test uses wmic.exe to execute a process on the local host. When the test completes ,a new process will be started locally .A notepad application will be started when input is left on default.
-	Solarigate persistence is achieved via backdoors deployed via various techniques including using PowerShell with an EncodedCommand Powershell -nop -exec bypass -EncodedCommand Where the –EncodedCommand, once decoded, would resemble: Invoke-WMIMethod win32_process -name create -argumentlist ‘rundll32 c:\windows\idmu\common\ypprop.dll _XInitImageFuncPtrs’ -ComputerName WORKSTATION The EncodedCommand in this atomic is the following: Invoke-WmiMethod -Path win32_process -Name create -ArgumentList notepad.exe You should expect to see notepad.exe running after execution of this test. Solarigate Analysis from Microsoft
-	This test uses wmic.exe to execute a process on a remote host (127.0.0.1 only in our case). This test will throw an error.
2.3.3.	Detection
Detecting T1047 - Windows Management Instrumentation attacks involves monitoring and analysing WMI activity. Here are some methods to detect this technique:
-	WMI Event Logs: Enable and analyse WMI event logs to identify suspicious or unusual WMI activity, such as the creation of new WMI processes, unauthorized script executions, or WMI queries from unusual sources.
-	Endpoint Detection and Response (EDR): Implement EDR solutions that can monitor and alert on suspicious WMI activity in real-time. Look for patterns of behaviour that indicate malicious intent, such as creating and executing WMI scripts.
-	Behavioural Analysis: Utilize behavioural analysis to detect anomalies, such as abnormal WMI activity, especially when it deviates from known good patterns.
-	Access Controls: Enforce access controls on WMI namespaces and objects to restrict who can execute WMI queries and commands. Limit permissions to only trusted users and processes.
-	Command and Script Analysis: Analyse WMI commands and scripts for malicious intent, such as attempts to access sensitive data, execute malicious code, or modify system settings.
-	Heuristic Detection: Employ heuristic or signature-based detection methods to identify known malicious WMI scripts or sequences of WMI commands used in attacks.
2.3.4.	Prevention
Preventing T1047 - Windows Management Instrumentation attacks require securing and controlling access to WMI:
-	Access Control: Implement strict access controls for WMI namespaces, classes, and objects. Only allow authorized users and processes to interact with WMI. Regularly review and update these permissions.
-	Audit and Monitoring: Continuously monitor and audit WMI activity on systems. Log all WMI queries and executions to detect any unauthorized or suspicious activity promptly.
-	Script Validation: If using WMI scripts, ensure they are well-vetted, and validate scripts before execution to prevent the use of malicious or untrusted scripts.
-	Least Privilege: Apply the principle of least privilege to limit the permissions and capabilities of user accounts and processes, reducing the potential impact of WMI misuse.
-	Endpoint Security: Employ endpoint security solutions capable of detecting and blocking malicious WMI activity. These solutions can help mitigate the risk of adversaries abusing WMI.
-	User Education: Educate users and administrators about the potential risks associated with WMI and the importance of only running authorized WMI scripts.
-	Network Segmentation: Isolate critical systems and networks to limit lateral movement if an attacker gains access to WMI on one system.
-	Regular Patching: Keep Windows systems up-to-date with security patches to address known vulnerabilities that attackers might exploit via WMI.

By combining these detection and prevention strategies, organizations can strengthen their defences against T1047 - Windows Management Instrumentation attacks, minimizing the risk of misuse of WMI for malicious purposes.
 
2.4.	T1027 - Obfuscated Files or Information
2.4.1.	Description
Tactic: Defense Evasion
Technique: Obfuscated Files or Information
Platform: Windows, Linux, macOS, Others
2.4.2.	Attack Description
T1027 - Obfuscated Files or Information represents a tactic where adversaries employ obfuscation techniques to hide malicious code, scripts, or data within files or information. Obfuscation is used to make it challenging for security tools to detect and analyse the malicious content, allowing attackers to evade detection and execute their payloads.
Scenario:
-	Mimic execution of compressed executable. When successfully executed, calculator.exe will open.
-	Stores base64-encoded PowerShell code in the Windows Registry and deobfuscates it for execution. This is used by numerous adversaries and malicious tools. Upon successful execution, powershell will execute encoded command and read/write from the registry, finally writes to console “Hello Cytrac!”.
2.4.3.	Detection
Detecting T1027 - Obfuscated Files or Information attacks involves identifying and decoding hidden or obfuscated content. Here are some methods to detect this technique:
-	Signature-Based Detection: Utilize signatures and patterns to identify known obfuscation techniques and common evasion methods. Antivirus and intrusion detection systems often employ these signatures.
-	Content Analysis: Analyse the content of files, scripts, or data for unusual patterns or encoding schemes. Look for characteristics indicative of obfuscation, such as base64 encoding, XOR operations, or excessive compression.
-	Heuristic Analysis: Employ heuristic analysis to detect patterns or behaviours that deviate from normal or benign files. Unusual file sizes, excessive entropy, or suspicious file naming conventions may indicate obfuscation.
-	Behavioural Analysis: Monitor the behaviour of files or processes. Look for processes attempting to execute obfuscated scripts or attempting to access hidden data, especially when it involves unusual system interactions.
-	Sandbox Analysis: Use sandbox environments to analyse suspicious files or content. Sandboxes can often identify obfuscated code or behaviour when executed in controlled environments.
2.4.4.	Prevention
Preventing T1027 - Obfuscated Files or Information attacks involves implementing measures to reduce the effectiveness of obfuscation techniques:
-	Content Inspection: Employ content inspection and analysis tools to scan files and scripts for obfuscated content. These tools can detect and decode obfuscated data before it executes.
-	Whitelisting: Implement application and script whitelisting to allow only trusted and approved files and scripts to execute. This can prevent the execution of untrusted or obfuscated code.
-	Security Software: Utilize advanced endpoint security solutions that incorporate machine learning and behaviour analysis to detect and block obfuscated threats.
-	Patch and Update: Keep software, including operating systems and applications, up to date to reduce the likelihood of known vulnerabilities being exploited through obfuscated files.
-	User Training: Educate users about the risks of opening or executing files from untrusted sources and encourage them to report suspicious files or behaviour.
-	Sandboxing: Isolate potentially risky files or scripts in sandbox environments before allowing them to execute in the production environment.
-	Security Policies: Develop and enforce security policies that restrict the use of known obfuscation techniques and encourage secure coding practices.
-	Behavioural Analytics: Implement behavioural analytics to identify unusual file or script behaviour that may indicate obfuscation or evasion attempts.

By combining these detection and prevention strategies, organizations can enhance their ability to detect and mitigate T1027 - Obfuscated Files or Information attacks, reducing the risk of attackers successfully hiding and executing malicious code or data.
 
2.5.	T1218.011 - Rundll32
2.5.1.	Description
Tactic: Defense Evasion
Technique: Signed Binary Proxy Execution
Sub-Technique: Rundll32
Platform: Windows
2.5.2.	Attack Description
T1218.011 focuses on adversaries abusing the Windows utility "Rundll32.exe" for executing malicious code or loading malicious DLLs (Dynamic Link Libraries). Rundll32 is a legitimate and commonly used Windows program designed to load and execute functions from DLLs but can be exploited by attackers to evade detection and run malicious code.
Scenario:

2.5.3.	Detection
Detecting T1218.011 - Rundll32 attacks involves monitoring the execution of Rundll32 and its associated parameters. Here are some methods to detect this technique:
-	Command Line Logging: Enable and monitor Windows command-line logging or use Sysmon to capture Rundll32 execution commands and their arguments. Look for suspicious or unusual command lines.
-	Behavioural Analysis: Utilize behavioural analysis to identify anomalous behaviour associated with Rundll32, such as Rundll32 being used to load unfamiliar or unsigned DLLs.
-	Code Signature Verification: Verify the digital signatures of DLLs loaded by Rundll32. Unsigned or suspicious signatures can indicate malicious activity.
-	Heuristic Analysis: Use heuristic or pattern-based detection methods to identify known malicious DLLs or DLL loading techniques used in attacks.
-	Parent-Child Relationship: Monitor the parent-child relationship of processes. Detect when Rundll32 is spawned by suspicious or unauthorized processes.
2.5.4.	Prevention
Preventing T1218.011 - Rundll32 attacks involves implementing measures to control and restrict the use of Rundll32 for malicious purposes:
-	Application Whitelisting: Employ application control or whitelisting solutions to allow only trusted and approved applications, including Rundll32, to execute. Block the execution of unauthorized or suspicious instances of Rundll32.
-	Code Signing: Digitally sign DLLs to ensure their authenticity. Configure systems to validate the digital signatures of DLLs loaded by Rundll32. Reject DLLs without valid signatures.
-	Command Line Restrictions: Implement restrictions on the use of Rundll32 through command line policies. Limit the execution of Rundll32 commands to known and authorized use cases.
-	Behavioural Analytics: Utilize behavioural analytics to detect unusual or suspicious Rundll32 behaviour, such as unexpected DLL loading patterns or executions from non-standard locations.
-	User Training: Educate users and administrators about the risks of executing Rundll32 commands from untrusted sources and encourage them to report suspicious behaviour.
-	Regular Patching: Keep the operating system and applications up to date to mitigate known vulnerabilities that attackers might exploit through Rundll32.
-	Access Controls: Enforce strict access controls on DLLs and the Rundll32 utility, limiting access to only authorized users and processes.

By implementing these detection and prevention strategies, organizations can enhance their ability to detect and mitigate T1218.011 - Rundll32 attacks, reducing the risk of adversaries exploiting Rundll32 for malicious purposes.
 
2.6.	T1105 - Ingress Tool Transfer
2.6.1.	Description
Tactic: Initial Access
Technique: Ingress Tool Transfer
Platform: Windows
2.6.2.	Attack Description
T1105 - Ingress Tool Transfer represents an attacker's efforts to transfer and install tools or malicious code onto a compromised system for the purpose of gaining initial access or maintaining persistence. This technique involves adversaries delivering and executing tools or payloads on the target system to establish control.
2.6.3.	Detection
Detecting T1105 - Ingress Tool Transfer attacks involve monitoring for suspicious file transfers, downloads, or executions. Here are some methods to detect this technique:
-	Network Traffic Analysis: Monitor network traffic for unusual or unauthorized data transfers, especially those involving suspicious file extensions or archives commonly used for tool delivery (e.g., executables, scripts, compressed files).
-	Endpoint Detection and Response (EDR): Utilize EDR solutions to track and log suspicious processes or file executions that may indicate the transfer and installation of malicious tools.
-	File System Monitoring: Implement file system monitoring to detect the creation or modification of files in system directories or other locations commonly used for tool installation.
-	Command Line Logging: Enable command line and script execution logging to capture commands or scripts responsible for tool transfer and execution.
-	Behavioural Analytics: Use behavioural analytics to identify unusual patterns, such as a sudden increase in file transfer activities or suspicious execution sequences.
2.6.4.	Prevention
Preventing T1105 - Ingress Tool Transfer attacks involve implementing measures to control and restrict the installation of unauthorized tools or payloads:
-	Application Whitelisting: Implement application control or whitelisting solutions to allow only trusted and approved applications to run. Block the execution of unapproved or suspicious tools.
-	Network Segmentation: Isolate critical systems and networks to limit lateral movement in case an attacker gains access to a system and attempts to transfer tools to other systems.
-	Access Controls: Enforce strict access controls on sensitive directories and locations where tools are commonly installed. Restrict write and execute permissions to authorized users and processes.
-	Content Inspection: Employ content inspection and filtering to scan incoming network traffic for known malicious tools or payloads, blocking them before they reach the target system.
-	User Training: Educate users and administrators about the risks associated with downloading or executing unverified tools and payloads and encourage them to report suspicious activities.
-	Regular Patching: Keep the operating system, applications, and software up to date to address known vulnerabilities that attackers might exploit during tool transfers.
-	Email and Web Filtering: Use email and web filtering solutions to block malicious attachments and links that could lead to the downloading and execution of tools.
By implementing these detection and prevention strategies, organizations can enhance their ability to detect and mitigate T1105 - Ingress Tool Transfer attacks, reducing the risk of adversaries successfully transferring and executing malicious tools on their systems.
 
2.7.	T1055 - Process Injection
2.7.1.	 Description
Tactic: Execution
Technique: Process Injection
Platform: Windows, Linux, macOS, Others
2.7.2.	Attack Description
T1055 - Process Injection is a technique where adversaries inject malicious code or payloads into the memory space of running processes. This allows attackers to execute code within the context of another process, evade detection, and gain control over a compromised system.
2.7.3.	Detection
Detecting T1055 - Process Injection attacks involve monitoring and identifying suspicious code injection activities. Here are some methods to detect this technique:
-	Memory Analysis: Employ memory analysis tools and techniques to scan the memory space of running processes for signs of injected code, such as unfamiliar code segments, unusual memory allocations, or code that does not belong to the legitimate process.
-	Behavioural Analysis: Use behavioural analysis to detect unusual process behaviour, such as processes spawning child processes with injected code, unexpected memory write operations, or attempts to access privileged system resources.
-	API Hooking Detection: Monitor for API hooking, detouring, or patching techniques often employed by attackers during process injection. Look for modifications to system or process API calls.
-	Suspicious Process Relationships: Analyse process relationships to identify suspicious parent-child process connections, especially those involving common injection techniques like CreateRemoteThread or SetThreadContext.
-	Command Line Logging: Enable command-line and script execution logging or use Sysmon to capture commands responsible for initiating process injection.
2.7.4.	Prevention
Preventing T1055 - Process Injection attacks involve implementing measures to reduce the risk of malicious code injection:
-	Least Privilege: Apply the principle of least privilege to limit the permissions and capabilities of user accounts and processes, reducing the potential impact of injected code.
-	Patch and Update: Keep the operating system, applications, and software up to date to address known vulnerabilities that attackers might exploit during the injection process.
-	Memory Protections: Implement memory protection mechanisms, such as Data Execution Prevention (DEP) and Address Space Layout Randomization (ASLR), to make it more difficult for attackers to inject and execute malicious code.
-	Code Signing: Digitally sign and verify the signatures of executable code to ensure the authenticity and integrity of processes and modules.
-	Behavioural Analytics: Employ behavioural analytics to identify unusual process behaviour, such as process injection indicators, and trigger alerts or automated responses.
-	Application Whitelisting: Implement application control or whitelisting solutions to allow only trusted and approved applications to run, limiting the execution of unauthorized code.
-	Access Controls: Enforce strict access controls on sensitive system resources and processes to prevent unauthorized access and modification.
-	Network Segmentation: Isolate critical systems and networks to limit lateral movement if an attacker gains access to a system and attempts process injection.
By combining these detection and prevention strategies, organizations can enhance their ability to detect and mitigate T1055 - Process Injection attacks, reducing the risk of adversaries successfully injecting malicious code into running processes.
 
2.8.	T1569.002 - Service Execution
2.8.1.	Description
Tactic: Execution
Technique: Service Execution
Platform: Windows
2.8.2.	Attack Description
T1569.002 represents an attacker's ability to execute malicious code or commands by manipulating Windows services. Adversaries may exploit vulnerable services or create new, malicious services to execute code and maintain persistence on a compromised system.
2.8.3.	Detection
Detecting T1569.002 - Service Execution attacks involve monitoring and identifying suspicious service-related activities. Here are some methods to detect this technique:
-	Service Configuration Changes: Continuously monitor for changes in service configurations, including the creation of new services or modifications to existing ones. Look for changes in the service binary path or startup type.
-	Anomalous Service Behaviour: Use behavioural analysis to identify unusual behaviour related to services, such as services being started or stopped unexpectedly or services attempting to execute unfamiliar or unauthorized code.
-	Service Account Changes: Monitor for changes to the service account associated with a service. Unexpected changes in service account privileges can be indicative of an attack.
-	Access Controls: Enforce strict access controls on service-related files, directories, and registry keys to limit unauthorized access and modification.
-	Behavioural Analytics: Implement behavioural analytics to detect unusual patterns of service activity, such as a service invoking suspicious system commands or attempting to access restricted resources.
2.8.4.	Prevention
Preventing T1569.002 - Service Execution attacks involve implementing measures to secure and control services:
-	Regular Patching: Keep the operating system and installed services up to date to address known vulnerabilities that attackers might exploit.
-	Least Privilege: Apply the principle of least privilege to service accounts, limiting their permissions and capabilities to reduce the potential impact of service-based attacks.
-	Service Hardening: Disable unnecessary services and features, especially those with known vulnerabilities or limited use in the organization.
-	Monitoring and Logging: Enable and configure service-related logging to capture events and changes in service configurations. Centralize and analyse logs to detect and respond to suspicious activities.
-	Access Controls: Implement strict access controls on service binaries, configuration files, and registry keys to prevent unauthorized modification.
-	Whitelisting: Employ application and script whitelisting solutions to restrict the execution of authorized services and binaries, blocking unapproved or malicious code.
-	Service Account Management: Implement rigorous service account management practices, including regular review and audit of service account privileges and configurations.
-	User Training: Educate users and administrators about the risks associated with service execution and the importance of only running authorized services.
By implementing these detection and prevention strategies, organizations can enhance their ability to detect and mitigate T1569.002 - Service Execution attacks, reducing the risk of adversaries successfully manipulating services to execute malicious code or maintain persistence.
 
2.9.	T1036.003 - Rename System Utilities
2.9.1.	Description
Tactic: Defense Evasion
Technique: Masquerading
Sub-Technique: Rename System Utilities
Platform: Windows
2.9.2.	Attack Description
T1036.003 - Rename System Utilities is a sub-technique where adversaries modify the names or paths of legitimate system utilities or executables to evade detection and perform malicious activities. By renaming system utilities, attackers can make them appear benign and evade security controls that rely on known file names or paths.
2.9.3.	Detection
Detecting T1036.003 - Rename System Utilities attacks involve monitoring for changes in file names or paths of system utilities. Here are some methods to detect this technique:
-	File System Monitoring: Continuously monitor the file system for changes in the names or paths of known system utilities. Look for unusual or unauthorized modifications.
-	Integrity Monitoring: Implement integrity monitoring solutions to track changes in critical system files, including system utilities. Detect and alert on unexpected modifications.
-	Command Line Logging: Enable command-line and script execution logging to capture commands responsible for renaming system utilities or accessing modified file paths.
-	Behavioural Analysis: Utilize behavioural analysis to detect unusual behaviour related to system utilities, such as renamed utilities being executed in an unusual context or by unauthorized processes.
-	File Hash Comparison: Maintain a database of known file hashes for system utilities. Use file hash comparison to detect changes in utility files, including those with modified names.
2.9.4.	Prevention
Preventing T1036.003 - Rename System Utilities attacks involve implementing measures to secure and control system utilities:
-	File Integrity Monitoring: Implement file integrity monitoring solutions to detect and alert on changes to critical system files, including system utilities. Ensure these solutions include checks for file name and path changes.
-	Application Whitelisting: Employ application and script whitelisting solutions to allow only trusted and approved system utilities to execute. Block the execution of unapproved or renamed utilities.
-	Access Controls: Enforce strict access controls on system utility files and directories, limiting access and modification permissions to authorized users and processes.
-	Regular Patching: Keep the operating system and software up to date to address known vulnerabilities that attackers might exploit through renamed system utilities.
-	User Training: Educate users and administrators about the risks associated with modifying or renaming system utilities and the importance of using approved and unaltered utilities.
-	Monitoring and Logging: Enable and configure monitoring and logging of file system changes, command-line activity, and process behaviour to capture and analyse suspicious actions related to system utilities.
By implementing these detection and prevention strategies, organizations can enhance their ability to detect and mitigate T1036.003 - Rename System Utilities attacks, reducing the risk of adversaries successfully renaming system utilities to evade detection and carry out malicious activities.
 
2.10.	T1003.001 - LSASS Memory
2.10.1.	Description
Tactic: Credential Access
Technique: Credential Dumping
Sub-Technique: LSASS Memory
Platform: Windows
2.10.2.	Attack Description
T1003.001 focuses on adversaries targeting the Local Security Authority Subsystem Service (LSASS) memory on Windows systems. LSASS is responsible for security-related functions, including user authentication. Attackers aim to extract sensitive credential information stored in the LSASS memory, such as usernames and passwords, to gain unauthorized access.
2.10.3.	Detection
Detecting T1003.001 - LSASS Memory attacks involves monitoring for suspicious activities related to the LSASS process and memory. Here are some methods to detect this technique:
-	Memory Dump Analysis: Monitor for attempts to dump the LSASS memory using tools or techniques like Mimikatz. Regularly analyse memory dumps for signs of credential theft.
-	Process Monitoring: Continuously monitor the LSASS process for suspicious behaviour (e.g.: with Sysmon), such as unauthorized access, code injection, or unusual process interactions.
-	Privilege Escalation: Detect privilege escalation attempts, as attackers may need elevated privileges to access and dump LSASS memory.
-	Credential Use Anomalies: Implement behavioural analytics to identify unusual credential use patterns, such as credentials being used from new or unexpected locations.
-	Event Log Analysis: Analyse Windows event logs for events related to LSASS process activities, especially those indicating memory access or credential dumping.
2.10.4.	Prevention
Preventing T1003.001 - LSASS Memory attacks involves implementing measures to protect LSASS memory and sensitive credentials:
-	Credential Guard: Use Windows Credential Guard (Windows 10 and later) or Virtualization-based Security (VBS) to protect LSASS memory and prevent unauthorized access to sensitive credentials.
-	Patch Management: Keep the operating system and software up-to-date to address known vulnerabilities that attackers might exploit to access LSASS memory.
-	Least Privilege: Apply the principle of least privilege to limit user and process permissions, reducing the risk of unauthorized access to LSASS memory.
-	Application Whitelisting: Employ application control or whitelisting solutions to restrict the execution of unauthorized or malicious tools, including those used for memory dumping.
-	Endpoint Detection and Response (EDR): Utilize EDR solutions to monitor and respond to suspicious LSASS process activities and detect attempts to access LSASS memory.
-	Network Segmentation: Isolate critical systems and networks to limit lateral movement if an attacker gains access to LSASS memory.
-	User Training: Educate users and administrators about the risks associated with credential theft and the importance of strong password practices.
-	Multi-Factor Authentication (MFA): Implement MFA to reduce the risk of stolen credentials being used for unauthorized access.
By combining these detection and prevention strategies, organizations can enhance their ability to detect and mitigate T1003.001 - LSASS Memory attacks, reducing the risk of adversaries successfully extracting sensitive credentials from LSASS memory.
 
# 3.	Usage
Simply download the file from Github (https://github.com/blackcellltd/cytractop10testagent), install it and run on the target or a UAT system where the measured IT security test in place. (“Run as administrator” is advised for the full results.).
Put either valid or wrong credentials when prompt pops up. 
All dependencies are included in the program's installation package except: Mimikatz, and Bloodhound libraries.
To fully utilize the features, the test host need active internet connection to let the tool download libraries from Github via HTTPS.
**The installed Cytrac Test Agent can be uninstalled from via the regular “Add or remove programs” control panel item. **
Different antivirus or endpoint security solutions can detect and categorize the executable itself as unwanted application or any type of malware. The file doesn’t contain any malware and can be whitelisted before the first run. See the Disclaimer below.

# 4.	Disclaimer: Use of the TOP 10 Adversarial Technique Test Agent
The TOP 10 Adversarial Technique Test Agent is designed for the purpose of evaluating the effectiveness of Security Operations Centres (SOCs) and IT security services/products. It is essential to note that this tool has been developed with a strict focus on non-destructive functions and does not include any scripts or capabilities that could potentially harm systems, data, or networks.
The following functions are included in the TOP 10 Adversarial Technique Test Agent:
-	clearScreen: Clears the screen.
-	addJson: Adds JSON text to the global character chain.
-	getTechniqueJson: Converts the results of a executed technique into JSON format.
-	clean: Post-execution, clears the contents of the "C:/temp" directory, excluding the "Tool" directory.
-	findDirectory: Locates the directory where the target program is located and executes it.
-	searchStringInOutput: Allows the specification of output results during execution.
-	runPowerShellCommand: Executes PowerShell commands.
-	executeCommand: Runs command-line programs.
-	escapeJsonString: Formats strings for JSON files.
-	saveToJsonFile: Saves data to a JSON file.
Connected URLs by cytrac.exe:
-	raw.githubusercontent.com/PowerShellMafia/PowerSploit
-	raw.githubusercontent.com/BloodHoundAD/BloodHound
-	bit.ly…

# Possible Antivirus or IDPS detections:

While running:

-	"Mimikatz credential theft tool"
-	"Bloodhound post-exploitation tool"
-	"Virus/Win32.WGeneric"
  
After extract:

-	"EUS:Win32/CustomEnterpriseBlock"

Additional folders created by the agent:
-	C:\temp\
This folder and the contents will be removed by the agent uninstaller. Else it needs to be removed manually.

Users and organizations employing the TOP 10 Adversarial Technique Test Agent should exercise caution and adhere to legal and ethical guidelines when using this tool. It is intended exclusively for security testing, validation, and research purposes. Any misuse of this tool for malicious activities is strictly prohibited and unlawful.
The authors and developers of the TOP 10 Adversarial Technique Test Agent shall not be held liable for any unintended or unauthorized use of the tool that results in harm to systems, data, or networks. Users are encouraged to use this tool responsibly and in accordance with applicable laws and regulations.
By utilizing this tool, users acknowledge and accept the non-destructive nature of its functions and commit to using it for legitimate and ethical security evaluation and research purposes.
This disclaimer should help clarify the scope and intent of the TOP 10 Adversarial Technique Test Agent while emphasizing its non-destructive nature.

