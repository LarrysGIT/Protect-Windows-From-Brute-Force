
import os
import sys
import time
import datetime 
import codecs
import win32evtlog
import win32con
from win32com.client import Dispatch
import re

MinutesToBack = 1
LogFolder = '.\Logs'
strLogFile = "$LogFolder\${strDate}.txt"
strLogFile_e = "$LogFolder\${strDate}_e.txt"

t_4625_fw = [30, 1]
#t_4625_fw_Intranet = [50, 1]
t_4625_fw_TimeoutDefault = 365 * 24 * 3600

def AddLog(Path, Type, Value):
	Type = Type.upper()
	log = codecs.open(Path, encoding='utf-8', mode='a')
	t = time.strftime('%Y-%m-%d %H:%M:%S')
	log.write("[" + t + "][" + Type + "] " + Value + "\n")
	print("[" + t + "][" + Type + "] " + Value)
	log.close()
	log = None

Now = datetime.datetime.now()
Flags = win32evtlog.EVENTLOG_BACKWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ
Handle = win32evtlog.OpenEventLog(None, 'Security')
Events = win32evtlog.ReadEventLog(Handle, Flags, 0)

### Add block rules start
l = {}
Break_ = False
while(Events and (not Break_)):
	for e in Events:
		if ((Now - datetime.datetime(*e.TimeGenerated.timetuple()[0:6])).seconds <= MinutesToBack * 60):
			if(e.EventID & 0x0000FFFF == 4625):
				if(e.StringInserts[-2] != '-'): # not "-" means ip
					if(e.StringInserts[-2] in l.keys()):
						l[e.StringInserts[-2]].append(e.StringInserts[5])
					else:
						l[e.StringInserts[-2]] = [e.StringInserts[5]]
				else: # - pass for now
					pass
		else:
			Break_ = True
	Events = win32evtlog.ReadEventLog(Handle, Flags, 0)

timeBlock = datetime.datetime.now() + datetime.timedelta(seconds=t_4625_fw_TimeoutDefault)
timeBlock = timeBlock.strftime('%Y-%m-%d %H:%M:%S')
for k in l.keys():
	if (len(l[k]) >= t_4625_fw[0] and len(set(l[k])) >= t_4625_fw[1]):
		# into fw
		strFWcmd = 'netsh.exe advfirewall firewall add rule name="ScriptAuto_' + k + '" dir=in action=block profile=any remoteip="' + k + '" description="' + timeBlock + '"'
		print(strFWcmd)
		os.system(strFWcmd)
Handle.close()
### Add block rules end

fwRules = [ i for i in Dispatch('HNetCfg.FwPolicy2').Rules if re.match('^ScriptAuto_(\d+?\.){3}\d+?$', i.name)]
### Remove timeout rules start
for i in fwRules:
	if re.match('^\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}$', i.description):
		timeBlock = datetime.datetime.strptime(i.description, '%Y-%m-%d %H:%M:%S')
		if (Now - timeBlock).total_seconds() >= 0:
			strFWcmd = 'netsh.exe advfirewall firewall delete rule name="' + i.name + '"'
			print(strFWcmd)
			os.system(strFWcmd)
	else:
		pass # fw rule's description not match datetime format
### Remove timeout rules end

### Blacklist start
if os.path.isfile('FW_Blacklist.txt'):
	f = open('FW_Blacklist.txt', 'r')
	arrBlack = f.readlines()
	f.close()
	arrBlack = [i.strip() for i in arrBlack]
	for i in arrBlack:
		strFWcmd = 'netsh.exe advfirewall firewall add rule name="ScriptAuto_' + i + '" dir=in action=block profile=any remoteip="' + i + '"'
		print(strFWcmd)
		os.system(strFWcmd)
else:
	pass # FW_Blacklist.txt not exists
### Blacklist end

fwRules = [ i for i in Dispatch('HNetCfg.FwPolicy2').Rules if re.match('^ScriptAuto_(\d+?\.){3}\d+?$', i.name)]
### Whilelist start
if os.path.isfile('FW_Whilelist.txt'):
	f = open('FW_Whilelist.txt', 'r')
	arrWhile = f.readlines()
	f.close()
	for j in [fw for fw in fwRules if [i for i in arrWhile if re.search(i, fw.name) and re.search('(?i)Supper', i)]]:
		strFWcmd = 'netsh.exe advfirewall firewall delete rule name="' + j.name + '"'
		print(strFWcmd)
		os.system(strFWcmd)
else:
	pass # FW_Whilelist.txt not exists
### Whilelist end
