# Against-AD-Brute-Attack

Read first,
For summary, this script analysis event logs in passed X minutes and find out all events with id 4625, retrieve IP address and if there are IPs amounted exceed threshold, script block it using windows firewall. Basically, this script is not limited on Exchange CAS, it can be deployed on any server as long as 4625 auth failure generated.

You can adjust thresholds in the script, please note too strict thresholds could cause unexpected block impact normal users.
If you want remove IP from block, you can remove its rule from windows firewall, or, add the ip address to FW_WhiteList.txt as |supper format. See FW_WhiteList.txt for more.
Deploy this script on every CAS serving internet

# How to use
1 This is a script to protect your AD passwords from hacking over Exchange OWA
	if your exchange mailboxes are attacking by someone over a internet published OWA url, probably this script can save u
2 Wrote by larry.song@outlook.com with powershell based on Windows 2012 R2 standard
3 Change your powershell execution policy to "RemoteSigned" via cmdlet "Set-ExecutionPolicy -ExecutionPolicy RemoteSigned" - To allow the script run
4 Enable audit logging for your CAS servers via GPO - To log 4625 events
5 Enable Windows firewall - To block attacker's IP addresses
6 Set "Starter.cmd" invoked by task scheduler every 1 minute

'Python version' is a python wrote script for the same purpose, running faster but logging is not completed yet, this folder can be removed safely.

- Larry.Song@outlook.com
