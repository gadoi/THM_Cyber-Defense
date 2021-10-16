Task 9 Using LOKI and its Yara rule set 
- Scan file 1. Does Loki detect this file as suspicious/malicious or benign?
hint: cd /tools/Loki
python loki.py -p ~/suspicious-files/file1/ 
....
FILE: /home/cmnatic/suspicious-files/file1/ind3x.php SCORE: 70 TYPE: PHP SIZE: 80992                                                                    
FIRST_BYTES: 3c3f7068700a2f2a0a09623337346b20322e320a / <?php/*b374k 2.2                                                                                
MD5: 1606bdac2cb613bf0b8a22690364fbc5                                                                                                                   
SHA1: 9383ed4ee7df17193f7a034c3190ecabc9000f9f                                                                                                          
SHA256: 5479f8cd1375364770df36e5a18262480a8f9d311e8eedb2c2390ecb233852ad CREATED: Mon Nov  9 15:15:32 2020 MODIFIED: Mon Nov  9 13:06:56 2020 ACCESSED: Sat Oct 16 15:08:14 2021                                                                                                                                
REASON_1: Yara Rule MATCH: webshell_metaslsoft SUBSCORE: 70                                                                                             
DESCRIPTION: Web Shell - file metaslsoft.php REF: -                                                                                                     
MATCHES: Str1: $buff .= "<tr><td><a href=\\"?d=".$pwd."\\">[ $folder ]</a></td><td>LINK</t                                                              
[NOTICE] Results: 0 alerts, 1 warnings, 7 notices                                                                                                       
[RESULT] Suspicious objects detected!                                                                                                                   
[RESULT] Loki recommends a deeper analysis of the suspicious objects.
answer:suspicious


- What Yara rule did it match on?
webshell_metaslsoft


- What does Loki classify this file as?
Web Shell


- Based on the output, what string within the Yara rule did it match on?
Str1


- What is the name and version of this hack tool?
b374k 2.2



- Inspect the actual Yara file that flagged file 1. Within this rule, how many strings are there to flag this file?
1



Scan file 2. Does Loki detect this file as suspicious/malicious or benign?
hint: python loki.py -p ~/suspicious-files/file2/
[INFO] Initializing all YARA rules at once (composed string of all rule files)                                                                          
[INFO] Initialized 652 Yara rules                                                                                                                       
[INFO] Reading private rules from binary ...                                                                                                            
[NOTICE] Program should be run as 'root' to ensure all access rights to process memory and file objects.                                                
[NOTICE] Running plugin PluginWMI                                                                                                                       
[NOTICE] Finished running plugin PluginWMI                                                                                                              
[INFO] Scanning /home/cmnatic/suspicious-files/file2/ ...                                                                                               
[NOTICE] Results: 0 alerts, 0 warnings, 7 notices                                                                                                       
[RESULT] SYSTEM SEEMS TO BE CLEAN. 
answer: benign


- Inspect file 2. What is the name and version of this web shell?
hint: head -n 20 ~/suspicious-files/file2/1ndex.php
b374k 3.2.3


#Task 10 Creating Yara rules with yarGen 
cd ~/tools/yarGen
python3 yarGen.py -m /home/cmnatic/suspicious-files/file2 --excludegood -o /home/cmnatic/suspicious-files/file2.yar

- From within the root of the suspicious files directory, what command would you run to test Yara and your Yara rule against file 2?
hint:
cd ~/suspicious-files/
answer: yara file2.yar file2/1ndex.php


- Did Yara rule flag file 2? (Yay/Nay)
Yay


- Copy the Yara rule you created into the Loki signatures directory.
hint: cd ~/suspicious-files/
cp file2.yar ~/tools/Loki/signature-base/yara/


- Test the Yara rule with Loki, does it flag file 2? (Yay/Nay)
Yay


- What is the name of the variable for the string that it matched on?
hint: sudo python ~/tools/Loki/loki.py -p ~/suspicious-files/file2
...
FILE: ../../suspicious-files/file2/1ndex.php SCORE: 70 TYPE: PHP SIZE: 223978                                                                           
FIRST_BYTES: 3c3f7068700a2f2a0a09623337346b207368656c / <?php/*b374k shel                                                                               
MD5: c6a7ebafdbe239d65248e2b69b670157                                                                                                                   
SHA1: 3926ab64dcf04e87024011cf39902beac32711da                                                                                                          
SHA256: 53fe44b4753874f079a936325d1fdc9b1691956a29c3aaf8643cdbd49f5984bf CREATED: Mon Nov  9 15:16:03 2020 MODIFIED: Mon Nov  9 13:09:18 2020 ACCESSED: Sat Oct 16 14:49:41 2021                                                                                                                                
REASON_1: Yara Rule MATCH: _home_cmnatic_suspicious_files_file2_1ndex SUBSCORE: 70                                                                      
DESCRIPTION: file2 - file 1ndex.php REF: https://github.com/Neo23x0/yarGen                                                                              
MATCHES: Str1: var Zepto=function(){function G(a){return a==null?String(a):z[A.call(a)]||"object"}function H(a){return G(a)=="function"}fun Str2: $c ... (truncated)                                                                                                                                            
[NOTICE] Results: 0 alerts, 1 warnings, 7 notices                                                                                                       
[RESULT] Suspicious objects detected!                                                                                                                   
[RESULT] Loki recommends a deeper analysis of the suspicious objects.

answer: Zepto

- Inspect the Yara rule, how many strings were generated?
cat file2.yar
20


- One of the conditions to match on the Yara rule specifies file size. The file has to be less than what amount?
hint: cat file2.yar 
700KB


#Task 11 Valhalla 
- Enter the SHA256 hash of file 1 into Valhalla. Is this file attributed to an APT group? (Yay/Nay)
hint: https://valhalla.nextron-systems.com/
paste: 5479f8cd1375364770df36e5a18262480a8f9d311e8eedb2c2390ecb233852ad
Yay


- Do the same for file 2. What is the name of the first Yara rule to detect file 2?
hint: 53fe44b4753874f079a936325d1fdc9b1691956a29c3aaf8643cdbd49f5984bf
paste https://valhalla.nextron-systems.com/
Webshell_b374k_rule1


- Examine the information for file 2 from Virus Total (VT). The Yara Signature Match is from what scanner?
hint: https://www.virustotal.com/gui/file/53fe44b4753874f079a936325d1fdc9b1691956a29c3aaf8643cdbd49f5984bf/details
--> community
THOR APT Scanner



- Enter the SHA256 hash of file 2 into Virus Total. Did every AV detect this as malicious? (Yay/Nay)
Nay


- Besides .PHP, what other extension is recorded for this file?
exe


- Back to Valhalla, inspect the Info for this rule. Under Statistics what was the highest rule match per month in the last 2 years? (YYYY/M)
hint: https://valhalla.nextron-systems.com/info/rule/Webshell_b374k_rule1
info --> Statics
2021/3


- What JavaScript library is used by file 2?
hint: view https://github.com/b374k/b374k/blob/master/index.php
Zepto


- Is this Yara rule in the default Yara file Loki uses to detect these type of hack tools? (Yay/Nay)
Nay




https://tryhackme.com/room/yara
https://www.thedutchhacker.com/yara-on-tryhackme/
