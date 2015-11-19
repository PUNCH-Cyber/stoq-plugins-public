rule Trojan_Hastati
{
	meta:
       		author = "FireEye Researchers"
        	alert = true
        	log = true
        	alert_severity = "HIGH"
        	type = "Malware"
        	description = "Yara signature to detect Korean DarkSeoul MBR wipr virus 20MAR2013."
       		cve = "n/a"
        	reference = "http://www.fireeye.com/blog/botnet-activities-outbreaks/2013/03/more-insights-on-the-recent-korean-cyber-attacks-trojan-hastati.html"
        	source = "FireEye"
        	weight = 100
        	version = 1
	strings:
        	$a = "taskkill /F /IM clisvc.exe"
        	$b = "taskkill /F /IM pasvc.exe"
        	$c = "shutdown -r -t 0"
	condition:
		all of them
}
