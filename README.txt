
## Protect your Windows server from password brute force attack
  Basically, if you create a windows server has 3389 opened to the internet, only running for few hours, you will surely find events `4625` from security logs, means someone was attempting to login the server.
  
  This powershell script works pretty well, it looks X minutes back and find all `4625` events and extract the IPs, defined by threshold settings in the script, hacker's IP address will be added to windows firewall with inbound connection block rule.

## how to use
  clone the repo somewhere on you server
  Task schduler to setup a job invoke the script every X minutes
  Update the script to set X minutes in the script
  Turn on windows firewall, run -> `wf.msc`
  Wait for few hours, you will find many blocked IPs in the inbound rules

