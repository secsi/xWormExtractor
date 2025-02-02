import clr
import sys
import base64
import hashlib
from Crypto.Cipher import AES
import re
from System.Reflection import ReflectionTypeLoadException

# Check if the script has at least one argument
if len(sys.argv) > 1:
    # Set the first argument as a variable
    assembly_path = sys.argv[1]
else:
    print("Where the file at brah?")
    quit()

def decrypt(input_str: str, mutex: str) -> str:
    if input_str is None: return "Not Set"
    key = bytearray(32)
    hash_digest = hashlib.md5(mutex.encode()).digest()
    key[:16] = hash_digest
    key[15:31] = hash_digest
    
    cipher = AES.new(bytes(key), AES.MODE_ECB)
    encrypted_data = base64.b64decode(input_str)
    decrypted_bytes = cipher.decrypt(encrypted_data)
    
    try:
        # Decode and strip junk
        decrypted_str = decrypted_bytes.decode(errors='ignore').rstrip("\x00")  # Removing null padding
        #Stripping crappy characters
        decrypted_str = ''.join(char for char in decrypted_str if char.isprintable())
        
        return decrypted_str
    except UnicodeDecodeError:
        return "[Decryption Error: Unable to decode UTF-8]"
        
def extract_utf16le_strings(assembly_path, min_length=4):
    # Rudimentary implementation of Floss Logic
    with open(assembly_path, "rb") as f:
        data = f.read()
    
    # UTF-16LE strings (even-byte sequences, ignoring nulls between ASCII chars)
    pattern = re.compile(rb'((?:[\x20-\x7E][\x00]){%d,})' % min_length)
    matches = pattern.findall(data)
    
    strings = [match.decode("utf-16le") for match in matches]
    
    return strings
    
def extract_utf8_strings(assembly_path, min_length=4):
    with open(assembly_path, "rb") as f:
        data = f.read()

    # Match sequences of ASCII printable or valid UTF-8 multi-byte characters
    pattern = re.compile(rb'[\x20-\x7E]+|(?:[\xC2-\xF4][\x80-\xBF]+)+')

    matches = pattern.findall(data)

    # Decode and filter short strings
    strings = [match.decode("utf-8", errors="ignore") for match in matches if len(match.decode("utf-8", errors="ignore")) >= min_length]

    return strings


if __name__ == "__main__":
    # Adding reference to the assembly
    try:
        clr.AddReference(assembly_path)  # Loading the assembly
    except Exception as e:
        print(f"Error loading assembly: {e}")
        sys.exit(1)

    # Importing necessary .NET namespaces
    from System.Reflection import Assembly

    # Load the assembly
    assembly = Assembly.LoadFrom(assembly_path)

    # Get the first module in the assembly
    module = assembly.GetModules()[0]
    
    appData = set()
    isObfuscated = False 
    
    # Check if obfusctaed
    try:
        module.GetTypes()
    except:
        print("[+] Obfuscated Payload")
        isObfuscated = True
    
    # If package is obfuscated then we need a different method
    if not isObfuscated:
        # Iterate over all types in the module
        for type_ in module.GetTypes():
            # Iterate through all members (fields, methods, etc.) in the type
            for member in type_.GetMembers():
                #isConnected and beyond is stuff we dont need
                if member.Name=="isConnected": break
                
                #run through the tokens and nab the data by name
                if 0x04000000 <= member.MetadataToken <= 0x040000FF:
                    #try: print(member.MetadataToken) 
                    #except: continue 
                    try: 
                        appData.add((member.Name,member.GetValue(None)))
                        #if its the mutex keep hold of it
                        if member.Name=="Mutex":
                            Mutex=member.GetValue(None)
                    except: continue 
    #                try: print(member.GetValue(None)) 
    #                except: continue 

        for item, value in list(appData):
            try: 
                decryptedVal = decrypt(value, Mutex)
                appData.remove((item, value))
                appData.add((item, decryptedVal))
                #print("decrypted "+name+" -> "+item)
            except: 
                # item likely unexncrypted or not of interest
                continue

        # Extract strings for profiling the xWorm Binary
        extracted_stringsUTF16 = extract_utf16le_strings(assembly_path)
        extracted_stringsUTF8 = extract_utf8_strings(assembly_path)
        
        #print(f"Mutex = {len(Mutex)}")
    
    #here we start with dissecting obfuscated payloads
    else:
        
        # Strings are located in UTF16 strings output. When obfuscation is in play they can be retrieved from there
        
        # Ant-Analysis -> "VirtualBox" and "vmware" in UTF16
        # Keylogger -> "OfflineKeylogger Not Enabled" if keylogger disabled UTF16
        # Extract strings for profiling the xWorm Binary
        extracted_stringsUTF16 = extract_utf16le_strings(assembly_path)
        extracted_stringsUTF8 = extract_utf8_strings(assembly_path)
        
        Mutex=""
        array = []
        
        for item in extracted_stringsUTF16:
            array.append(item)
        
        possibleMutex = []
        
        # loop through and use strings to decrypt other strings. Looking for a number which will be a port number (always set and always a number)
        for item in array:
            for item2 in array:
                try: 
                    val = decrypt(item,item2)
                    if val.isnumeric():
                        possibleMutex.append(item2)
                except:
                    continue
        
        print(f"[+] Found {len(possibleMutex)} potential encryption strings")
        
        # We may match the sleep integer and other numerics not port related.
        print("[+] Checking top stings for best chances")
        
        # Mutex is always 16 chars
        for potential in list(possibleMutex):
            if len(potential)!=16: possibleMutex.remove(potential)
        
        if len(possibleMutex)>1:
            print("[!] [!] [!] More than one mutex choice.... I am confused and will now terminate.")
            print(possibleMutex)
            ## TODO: Find a way of brute force matching against string types.
            quit()
        else: Mutex=possibleMutex[0]
        
        print(f"[+] Using {Mutex} as Encryption String\n\n")
        print(f"[+] USE COMMON SENSE AHEAD:\n\n")
        print(f"\t-> IP Address is like the C2(if set)\n\t-> After that will be a domain name (if set)\n\t-> Then a port number\n\t-> The rest are items youll need to manually guess what configs they are\n\n")
        
        
        
     # Print the extracted values
    if isObfuscated: print(f"[+] Binary is obfuscated")
    else: print(f"[+] Binary is unobfuscated")
    count = 0
    start = False
    for string in extracted_stringsUTF16:
        if string=="StringFileInfo": start=True
        if start: count+=1
    if count>14: print(f"[+] Binary has assembly configured")
    else: print(f"[+] Binary has no assembly configured")
        
    # If obuscated the C2 options need detecting differently
    if not isObfuscated:
        print("\n\n[+] C2 Connectivity:\n")
        print(f"Hosts: {next((value for item, value in appData if item == 'Hosts'), 'Not found')}")
        print(f"Host: {next((value for item, value in appData if item == 'Host'), 'Not found')}")
        print(f"Port: {next((value for item, value in appData if item == 'Port'), 'Not found')}")
        print(f"Key: {next((value for item, value in appData if item == 'KEY'), 'Not found')}") 
        print(f"Group: {next((value for item, value in appData if item == 'Group'), 'Not found')}")
        print(f"SPL: {next((value for item, value in appData if item == 'SPL'), 'Not found')}")
        
        print("\n\n[+] Builder Settings:\n")
        print(f"USB exe: {next((value for item, value in appData if item == 'USBNM'), 'Not found')}")
        print(f"Install Dir: {next((value for item, value in appData if item == 'InstallDir'), 'Not found')}")
        print(f"Install File: {next((value for item, value in appData if item == 'InstallStr'), 'Not found')}")
        print(f"Logger Path: {next((value for item, value in appData if item == 'LoggerPath'), 'Not found')}")
    else:            
        # Print the extracted values
        print("\n\n[+] C2 Connectivity and Builder Settings:\n")
        #now we have Mutex.... decode stuff 
        # TODO DECODE BASE64 VARS FOR SUFF
        for item in extracted_stringsUTF16:
            try:
                print(f"Config Element => {decrypt(item,Mutex)}")
            except:
                continue
        
    print("\n\n[+] Persistence Configurations\n")
    for string in extracted_stringsUTF16:
        if 'SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run' in string: print("Registry Persistence Enabled")
        if '/create /f /RL HIGHEST /sc minute /mo 1 /tn ' in string: print("Scheduled Task Persistence Enabled")
        if 'WScript.Shell' in string: print("Startup Folder Persistence Enabled")

    print("\n\n[+] Additional Configurations\n")
    if "RunAntiAnalysis" in extracted_stringsUTF8 and "DetectSandboxie" in extracted_stringsUTF8:
        print("Anti-Analysis is enabled")
    if "/sendMessage?chat_id=" in extracted_stringsUTF16:
        print(f"Telegram Bot Configured is configured\n\tChat ID: {next((value for item, value in appData if item == 'ChatID'), 'Not found - If obfuscated it will be shown further up')}\n\tToken: {next((value for item, value in appData if item == 'Token'), 'Not found - If obfuscated it will be shown further up')}")
    if "OfflineKeylogger Not Enabled" not in extracted_stringsUTF16:
        print("Keylogger enabled")
    if "WaitForExit" in extracted_stringsUTF8 and "Exclusion" in extracted_stringsUTF8 and "get_ModuleName" in extracted_stringsUTF8:
        print("WDEX Enabled")
    if "CriticalProcess_Enable" in extracted_stringsUTF8 and "ProcessCritical" in extracted_stringsUTF8 and "needSystemCriticalBreaks" in extracted_stringsUTF8:
        print("Anti kill enabled")

print("\n\n[+][+][+] Finished [+][+][+]\n")
