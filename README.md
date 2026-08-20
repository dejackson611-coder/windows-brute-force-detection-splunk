# 🔐 Windows Brute Force Detection & Investigation with Splunk

## Project Overview

This project demonstrates a hands-on Security Operations Center (SOC) investigation using Splunk Enterprise and Windows Security Event Logs.

The objective was to simulate repeated failed authentication attempts against a Windows domain user, ingest the resulting security events into Splunk, create a detection rule for potential brute-force activity, and investigate the authentication activity.

During the investigation, Windows Event ID **4625 (Failed Logon)** and Event ID **4624 (Successful Logon)** were analyzed to identify suspicious authentication behavior.

## Lab Objectives

- Generate failed Windows authentication attempts in a controlled lab environment
- Collect and analyze Windows Security logs using Splunk Enterprise
- Identify failed authentication events using Event ID 4625
- Build an SPL query to detect repeated login failures
- Create a scheduled Splunk alert for possible brute-force activity
- Investigate the events associated with the triggered alert
- Correlate failed logins with successful logins using Event IDs 4625 and 4624
- Document the investigation as a SOC analyst workflow

## Technologies Used

- Splunk Enterprise 10.4.1
- Windows 11
- Windows Security Event Logs
- Active Directory
- Oracle VirtualBox
- Splunk Search Processing Language (SPL)

## Lab Environment

The lab uses a virtualized Windows environment with centralized security-event monitoring through Splunk.

Authentication activity from the Windows system is collected and indexed in Splunk, allowing failed and successful login events to be searched, correlated, and used for alerting.

**Key Windows Security Events:**

- **Event ID 4625** — An account failed to log on
- **Event ID 4624** — An account was successfully logged on

## Brute-Force Detection

Windows authentication events were analyzed in Splunk to identify repeated failed login attempts against the domain account `jsmith`.

The investigation identified:

- **23 failed login attempts**
- **2 successful login events**
- Failed authentication activity identified using **Event ID 4625**
- Successful authentication activity identified using **Event ID 4624**

The repeated authentication failures followed by successful authentication demonstrate behavior that may warrant further investigation by a SOC analyst.

## SPL Detection Query

The following Splunk Search Processing Language (SPL) query was used to correlate failed and successful authentication activity:

```spl
index=main sourcetype="WinEventLog:Security" (EventCode=4625 OR EventCode=4624)
| mvexpand Account_Name
| search Account_Name="jsmith"
| eval Failed=if(EventCode=4625,1,0)
| eval Successful=if(EventCode=4624,1,0)
| stats sum(Failed) AS Failed_Attempts sum(Successful) AS Successful_Logins earliest(_time) AS First_Event latest(_time) AS Last_Event by Account_Name
| convert ctime(First_Event) ctime(Last_Event)
| table Account_Name Failed_Attempts Successful_Logins First_Event Last_Event
```

### Detection Results

![Splunk detection results showing 23 failed login attempts and 2 successful logins](screenshots/Final%20Detection%20%E2%80%94%2023%20Failed%20Attempts%20%2B%202%20Successful%20Logins.jpeg)
