# PCAP Investigation

## Objective

The objective of this cybersecurity project was to analyze a network traffic capture file (PCAP) suspected of containing malware by employing a comprehensive approach. I used Wireshark to examine network packets, identify anomalies, and pinpoint indicators of compromise. I leveraged PowerShell to generate and manage file hashes, and utilized VirusTotal to cross-reference these hashes against known malicious files. Additionally, I used Zui to view alerts related to the network traffic. My goal was to uncover and investigate potential malicious activity, understand the malware’s behavior and impact on the network, and enhance detection and response strategies for such threats.

### Skills Learned

- Proficient use of Wireshark for network packet analysis and anomaly detection.
- Skillful generation and management of file hashes using PowerShell.
- Effective cross-referencing and validation of file hashes using VirusTotal.
- Improved ability to detect and respond to network-based threats.
- Experience with Zui for monitoring and interpreting network alerts.

### Tools Used

- Wireshark to investigate and analyze the provided PCAP data.
- Zui to isolate and investigate alerts inside of the PCAP, uncovering more information about the suspected malware.
- Powershell to generate SHA256 file hashes to cross-reference with Virustotal.

## Steps
![Screenshot 2024-08-08 170215](https://github.com/user-attachments/assets/b1d0e01c-a018-4e40-af18-228525b280bd)

_**Ref 1:** Verified first/last packet time windows as good practice to ensure accurate analysis_

-----

![Screenshot 2024-08-08 171946](https://github.com/user-attachments/assets/35135433-fa71-479c-abab-87880ab58f04)

_**Ref 2:** Preliminary check of protocol hierarchy as a high level overview_

-----

![Screenshot 2024-08-08 172028](https://github.com/user-attachments/assets/8154359e-aaa9-4485-a673-03ae50f6acaf)

_**Ref 3:** Made note of the top "talkers" in the PCAP, notating all involved IP addresses_

-----

![Screenshot 2024-08-09 143303](https://github.com/user-attachments/assets/91ad93f9-ff05-48ca-a452-e2371ace9f41)
![Screenshot 2024-08-09 125319](https://github.com/user-attachments/assets/3e1842b0-d675-472a-bce0-de9d78e06342)

_**Ref 4:** Checked first DNS query on Virustotal, flagged as malicious with an IP origin of Russia_

-----

![Screenshot 2024-08-09 125451](https://github.com/user-attachments/assets/18ab72ef-8b30-4ca8-b81e-dd103b898c21)

_**Ref 5:** HTTP stream shows infamous "This program cannot be run in DOS mode." Indicative of portable exe_

-----

![Screenshot 2024-08-09 125549](https://github.com/user-attachments/assets/0b184cd8-75f2-4052-95d9-49c4344e9017)

_**Ref 6:** Filtered all HTTP traffic from the suspected malicious IP, finding a .rar_

-----

![Screenshot 2024-08-09 130048](https://github.com/user-attachments/assets/733fa161-cf66-4b79-89f1-a8b6c5da18e6)

_**Ref 7:** HTTP stream followed of second highest conversation IP's GET request_

-----

![Screenshot 2024-08-09 130112](https://github.com/user-attachments/assets/7b030cae-1876-4ac6-8160-79db0595a79d)

_**Ref 8:** Searched the shown domain on Virustotal, flagged as malicious with an IP origin of Russia again_

-----

![Screenshot 2024-08-09 130341](https://github.com/user-attachments/assets/f938d57d-f214-47b2-8168-926acca034b3)

_**Ref 9:** Client Hello filter applied for encrypted traffic, searched the SNI domain which also flagged as malicious on Virustotal_

-----

![Screenshot 2024-08-09 140223](https://github.com/user-attachments/assets/363621d7-814a-4f31-8c82-9d9403fc91e2)
![Screenshot 2024-08-09 140447](https://github.com/user-attachments/assets/092c1cca-7b23-41ae-ae47-aca6668dbd11)

_**Ref 10:** Opened the PCAP in Zui to isolate and investigate alerts, which showed a known malware signature_

-----

![Screenshot 2024-08-09 141320](https://github.com/user-attachments/assets/553735b5-a620-4f21-bed2-2e4e858a2ef2)

_**Ref 11:** Securely downloaded the malicious files to the VM, and generated hashes via PowerShell_

-----

![Screenshot 2024-08-09 141349](https://github.com/user-attachments/assets/0308cbbf-012b-4acd-bfec-ed25944109be)

_**Ref 12:** Searched Virustotal with the suspected malicious hash, which had an overwhelmingly malicious rating_

-----

![Screenshot 2024-08-09 141847](https://github.com/user-attachments/assets/94950357-3a1d-4dfb-bc48-52c76059e1ec)

_**Ref 13:** Project completion_
