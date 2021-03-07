# Process Network Connection Anomalies
**Author:** Cyb3rMonk ( [Medium](https://mergene.medium.com), [Twitter](https://twitter.com/Cyb3rMonk) )

Language: Azure KQL
Products: MDATP/MDE, Azure Sentinel (Sysmon)


## Description

Servers have a specific baseline. This makes it easy to create a baseline and detect anomalies.  
Below query analyzes network connections made by the processes and detects the rare ones.


**Query :**

```C#
// Define servers you want to monitor. 
let Servers = dynamic(["server1","server2","etc."]);
// Get rare connections by RemoteIP and InitiatingProcessFileName
DeviceNetworkEvents
| where Timestamp > ago(30d)
| where DeviceName in (Servers) and ActionType == "ConnectionSuccess"
| where RemoteIPType !in ( "Private", "Loopback" )
| where RemoteIP !startswith "169.254."
| summarize make_set(RemoteUrl), count() by RemoteIP, InitiatingProcessFileName
| where count_ < 50
// Exclude traffic to known destinations.
| where not ( set_RemoteUrl has_any (".microsoft.com",".windowsupdate.com","login.microsoftonline.com","login.live.com","autodiscover-s.outlook.com","ocsp.digicert.com","ocsp.verisign.com","login.windows.net", "outlook.office365.com","accounts.accesscontrol.windows.net"))
// Get details of the connections that were made in the last 5 days.
| join kind=inner
    (
    DeviceNetworkEvents
    | where Timestamp > ago(5d)
    | where DeviceName in (Servers) and ActionType == "ConnectionSuccess"
    | where RemoteIPType !in ( "Private", "Loopback" )
    | where RemoteIP !startswith "169.254."
    ) on RemoteIP
```
