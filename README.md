# Official [Cyber Range](http://joshmadakor.tech/cyber-range) Project

<img width="400" src="https://github.com/user-attachments/assets/44bac428-01bb-4fe9-9d85-96cba7698bee" alt="Tor Logo with the onion and a crosshair on it"/>

# Threat Hunt Report: Unauthorized TOR Usage
- [Scenario Creation](https://github.com/Moise2001/threat-hunting-scenario-tor/blob/main/threat-hunting-scenario-tor-event-creation.md)

## Platforms and Languages Leveraged
- Windows 10 Virtual Machines (Microsoft Azure)
- EDR Platform: Microsoft Defender for Endpoint
- Kusto Query Language (KQL)
- Tor Browser

##  Scenario

Management suspects that some employees may be using TOR browsers to bypass network security controls because recent network logs show unusual encrypted traffic patterns and connections to known TOR entry nodes. Additionally, there have been anonymous reports of employees discussing ways to access restricted sites during work hours. The goal is to detect any TOR usage and analyze related security incidents to mitigate potential risks. If any use of TOR is found, notify management.

### High-Level TOR-Related IoC Discovery Plan

- **Check `DeviceFileEvents`** for any `tor(.exe)` or `firefox(.exe)` file events.
- **Check `DeviceProcessEvents`** for any signs of installation or usage.
- **Check `DeviceNetworkEvents`** for any signs of outgoing connections over known TOR ports.

---

## Steps Taken

### 1. Searched the `DeviceFileEvents` Table

Searched the DeviceFileEvents for any file that had the string “tor” in it and discover what looks like the user employer installed a tor installer, did something that resulted in many tor related files being copied to the desktop and the creation of a file called “tor-shopping-list.txt” the events began at :2025-09-13T05:37:10.7049602Z.

**Query used to locate events:**

```kql
DeviceFileEvents
| where FileName startswith "tor"
| where DeviceName == "moaz2"
| order by Timestamp desc
```
<img width="1727" height="382" alt="image" src="https://github.com/user-attachments/assets/9ddb5682-802b-4946-ad1b-ce35726131dd" />

---

### 2. Searched the `DeviceProcessEvents` Table

Searched the DeviceProcessEvents table for any process that contains the string "tor-browser-windows-x86_64-portable-14.5.6  /S" 
 based on the logs returned at 
Sep 13, 2025 1:38:55 AM
An employee on moaz2 ran the file from their downloads and used silent installation


**Query used to locate event:**

```kql

DeviceProcessEvents
| where DeviceName == "moaz2"
| where ProcessCommandLine contains "tor-browser-windows-x86_64-portable-14.5.6  /S"
| project Timestamp, DeviceName, ActionType, FileName, ProcessCommandLine
```
<img width="952" height="72" alt="image" src="https://github.com/user-attachments/assets/ac01fc90-0d00-4198-a0fc-09ac19aeee95" />


---

### 3. Searched the `DeviceProcessEvents` Table for TOR Browser Execution

Searched DeviceProcessEvents table for any indications that user employee actually opened the tor browser there was evidence that they did open it at : 2025-09-13T05:39:55.6398787Z there were several instance of firefox (tor) as well as tor.exe spawned afterwards

**Query used to locate events:**

```kql
DeviceProcessEvents
| where DeviceName == "moaz2"
| where ProcessCommandLine has_any("tor.exe","firefox.exe")
| project  Timestamp, DeviceName, AccountName, ActionType, ProcessCommandLine
```
<img width="999" height="307" alt="image" src="https://github.com/user-attachments/assets/a26d52af-9cca-47ad-bbab-5274d918eb49" />


---

### 4. Searched the `DeviceNetworkEvents` Table for TOR Network Connections

Searched the DeviceNetworkEvents table for any indication the tor browser was used to establish a connection using any of the known tor ports


On September 13, 2025, at 1:42 AM, the device named moaz2 (logged in as user mo) ran a program called tor.exe, which connected to the remote IP address 45.32.4.66 on port 9001. There were a few other connections to other sig over port 443 as well

**Query used to locate events:**

```kql
DeviceNetworkEvents
| where DeviceName == "moaz2"
| where InitiatingProcessFileName in~ ("tor.exe", "firefox.exe")
| where RemotePort in (9001, 9030, 9040, 9050, 9051, 9150)
| project Timestamp, DeviceName, InitiatingProcessAccountName, InitiatingProcessFileName, RemoteIP, RemotePort, RemoteUrl
| order by Timestamp desc
```
<img width="1002" height="142" alt="image" src="https://github.com/user-attachments/assets/d90c2f08-c9e4-48de-afcb-e77c99ea9365" />


---

## Chronological Event Timeline 

Timeline of Events
1:37 AM – User mo on device moaz2 downloaded/renamed the Tor installer (tor-browser-windows-x86_64-portable-14.5.6.exe) into their downloads folder.


1:38 AM – The same user silently installed Tor using the command tor-browser-windows-x86_64-portable-14.5.6 /S.


1:39 AM – 1:40 AM – Multiple Tor-related files (e.g., tor.txt, Torbutton.txt, Tor-Launcher.txt) were created on the desktop under the Tor Browser folder. A tor-shopping-list.txt file was also created on the desktop.


1:39 AM – 1:41 AM – The user launched the Tor Browser (via firefox.exe), spawning multiple Firefox content processes.


1:42 AM – tor.exe initiated a network connection to external IP 45.32.4.66 on port 9001 (a known Tor entry node).


1:43 AM – firefox.exe established a SOCKS connection to 127.0.0.1:9150, which is Tor’s local proxy port, indicating active use of the Tor browser.


---

## Summary

The employee on device moaz2 deliberately downloaded and silently installed the Tor Browser. Soon after, they opened it and began browsing anonymously through the Tor network. Network activity confirms successful connections to a Tor relay on port 9001 and local SOCKS proxy on 9150. A suspicious text file named tor-shopping-list.txt was also created on the desktop, suggesting possible intentional activity tied to Tor use.

---

## Response Taken

TOR usage was confirmed on endpoint moaz2 by the user mo. The device was isolated and the user's direct manager was notified.

---
