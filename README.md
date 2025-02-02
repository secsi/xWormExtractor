
# xWorm Config Extractor

## Overview

This script is a proof-of-concept (PoC) tool for extracting configuration data from xWorm malware samples. Initially, the goal was to create a simple YARA rule to detect xWorm, but this evolved into a full Python-based config extractor capable of parsing multiple variants.

Only currently running under Windows, haven't ported to get it working in Linux yet. 

Corresponding Blog Post: http://blog.badoosb.com/xworm-decoder-extracting-configs-without-a-sandbox
## Features

- **Automated config extraction:** Retrieves C2, port, group membership, mutex, and other critical configuration values.
- **Obfuscation handling:** Uses string analysis and decryption techniques to extract obfuscated values.
- **Persistence detection:** Identifies enabled persistence methods (Registry, Scheduled Task, Startup Folder).
- **Feature extraction:** Determines enabled options such as:
	Anti-Analysis
	Keylogger
	Telegram Bot Integration - Extracts ChatID and Token
	Anti-Kill protections
	WDEX
	USB infection
- **Static analysis-based:** No need to execute the malware; extracts data purely from the binary. No more sandboxing workflows.

### Usage

#### Prerequisites

- Python 3.x
- pycryptodome
- pythonnet

#### Example usage:

```
python xworm_extractor.py "/full/path/to/file/sample.exe"
```

#### Sample Output

```
PS C:\Users\user\Desktop> .\xWorm_config_Extractor.py "C:\Users\user\Desktop\malware_likely_xworm.exe"
[+] Binary is unobfuscated
[+] Binary has no assembly configured

[+] C2 Connectivity:

Hosts: 123.123.123.123,bad-domain.com,another-bad-domain.com
Host: Not Set
Port: 65059
Key: <123456789>
Group: Not found
SPL: <Xwormmm>


[+] Builder Settings:

USB exe: USB.exe
Install Dir: %AppData%
Install File: explorer.exe
Logger Path: Not found


[+] Persistence Configurations

Registry Persistence Enabled
Startup Folder Persistence Enabled


[+] Additional Configurations

WDEX Enabled
Anti kill enabled


[+][+][+] Finished [+][+][+]
```

## YARA Rule

For those looking to detect xWorm samples, the following YARA rule can be used:

```
rule MAL_XWorm_RAT {
   meta:
      description = "Detect XWorm via multiple hardcoded user agent strings present in binaries as well as a hardcoded content length HTTP header field."
      author = "Dave Addison"
      date = "2025-01-25"
      SHA256-1 = "95e1104df5d9080402316949de1137c886f9d53d884cee12d10af499f41d5ac1"
	  SHA256-2 = "c77420f9b9a1c6dc4dfc36f2b72c575fb882339286c14bb85b79e86b2c2486bc"
   strings:
      $s1 = "Content-length: 5235" ascii wide
      $s2 = "Mozilla/5.0 (Windows NT 6.1; Win64; x64; rv:66.0) Gecko/20100101 Firefox/66.0" ascii wide
      $s3 = "Mozilla/5.0 (iPhone; CPU iPhone OS 11_4_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/11.0 Mobile/15E148 Safari/604.1" ascii wide
      $s4 = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/60.0.3112.113 Safari/537.36" ascii wide
   condition:
      all of them
}
```

## Contributions

This is a PoC and not a polished tool. If you can improve the error handling, speed, or overall efficiency, feel free to do so! The goal is to assist malware analysts in automating xWorm triage.
