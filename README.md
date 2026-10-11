# SleuthHound
SleuthHound is a modular Python parsing and detection engine designed to analyze raw SharpHound Active Directory JSON exports. Built to simplify domain security assessments, it automatically iterates through multi-run scan data, aggregates telemetry across timestamped prefixes, and flags high-risk security misconfigurations and attack paths; delivering structured, actionable output for blue team operators and defenders.

---

## What's New in v2.1
- **New Detection Modules**: Added targeted checks for Kerberoastable Accounts (SPN hunting) and DCSync Abuse (GetChanges/GetChangesAll rights normalization).
- **Multi-Run Telemetry Aggregation**: Enhanced dataset iteration across timestamped scan prefixes for multi-scan SharpHound runs.
- **Terminal UI Enhancements**: Added dynamic ASCII banner generation for a polished command-line experience.

---

## Hashes
For those who opts to download the file rather than populating their own:
- **`SleuthHound.py` SHA256**: `c67bb58944d19a00153994db98c562f58e301e7fc0eb9757d9b559a86b6ca443`
- **`SleuthHound.py` MD5**: `b13229ffc7cef436efb3599fb431d671`

### Integrity Verification
To verify the integrity of the download, simply run:
- **Windows**: `CertUtil -hashfile SleuthHound.py SHA256`
- **Linux/Mac**: `shasum -a 256 SleuthHound.py`

---

## Features & Detections
The current version of the script identifies the following vulnerabilities:
- **AS-REP Roasting**: Users that have `dontreqpreauth` set to True.
- **Unconstrained Delegation**: Computer objects trusted to impersonate users across the network. 
- **ACE Abuse**: Identification of dangerous permissions, such as `GenericAll`, `WriteDacl`, and `WriteOwner`. 
- **Machine Account Quota**: Identification of non-zero quotas on the Domain object. 
- **Outdated Operating Systems**: Detection of legacy systems (such as 2008, 2012, and more) based on the OS version strings.
- **Kerberoastable Accounts**: Detects user accounts with Service Principal Names set that are vulnerable to offline brute-force cracking of their service ticket hashes.
- **DCSync Abuse**: Identifies accounts with replication rights that can be abused to extract password hashes from the domain controller.

---

## Requirements
- **SleuthHound Home**: Ensure SleuthHound.py is properly setup in the appropriate directory with and input and output folder. You can create the home for it with:
```bash
mkdir SleuthHound; cd SleuthHound; mkdir input; mkdir output
```
- **Python 3.x**: Ensure Python is installed and added to your PATH. If you don't have Python setup, you can do so with:
### Windows
1. **Download**: Get the latest installer from python.org
2. **Install**: Run the `.exe`. 
  - **IMPORTANT**: Ensure you check the box that says "Add Python to PATH" at the bottom of the first installer screen. 
2.1 **Manual PATH Check (if you missed the box)**:
  - Search for "Environmental Variable" in the Start menu.
  - Select "Edit the system environment variables."
  - Click Environment Variables > Path > Edit > New
  - Paste your Python installation path (such as `C:\Users\<name>\AppData\Local\Programs\Python\Python314\`). 
4. **Verify**: Open PowerShell and type:
```bash
python --version
```
### Linux (Ubuntu/Debian)
Python is typically pre-installed. To ensure you have the latest version and it's in your path:
1. **Install**: 
```bash
sudo apt update && sudo apt install python3 -y
```

2. **Verify PATH**: Most Linux distros add `/usr/bin/python3` to the PATH automatically. Check this with:
```bash
python3 --version
```

3. **Manual Export (if needed)**: Add this to your `~/.bashrc` or `~/.zshrc`:
```bash
export PATH="$PATH:/usr/bin/python3"
```

- **SharpHound Data**: You must have the output JSON files. These must be extracted from the SharpHound zip and stored in the input directory. SleuthHound utilizes `users.json`, `computers.json`, and `domains.json` by default. 

---

## Setup and Usage
1. **Preparation**: Ensure your SharpHound JSON files are unzipped and located in the input directory. You can do so using with:
  - **Windows** (Replace `<sharphound_zip> with the appropriate file name. 
  ```bash
  Expand-Archive -Path ".\<sharphound_zip>.zip" -DestinationPath ".\input" -Force
  ```

  - **Linux (Terminal)**: If you don't have `unzip` installed, run `sudo apt install unzip` first. After, run:
  ```bash
  unzip <sharphound_zip>.zip -d ./input
  ```

2. **Run the Script**: In the SleuthHound directory, run the following command:
  - **Windows**:
  ```bash
  python SleuthHound.py
  ```

  - **Linux**:
  ```bash
  python3 SleuthHound.py
  ```


3. **Review Output**: SleuthHound will output a standardized list of vulnerabilities, including the type of risk, source of the risk, and the target object. Each of the five vulnerabilities are output into their own respective file as well as in a centralized `flags.txt` file. You can view these by using:
```bash
cd output && ls
```

---

## Source Code 
If you would prefer to create the file yourself, you can do so in two simple steps:
1. **Create the file**: In the SleuthHound directory, simply create the file with:
```bash
nano SleuthHound.py
```

2. **Populate the File**: Simply add the following script to your new file:

<details>
<summary>Click to expand SleuthHound.py Source Code</summary>
  
```python
import json
import os
import glob

# Folder paths
INPUT_FOLDER = "input"
OUTPUT_FOLDER = "output"

def get_scan_runs():
    domain_files = glob.glob(os.path.join(INPUT_FOLDER, "*_domains.json"))
    runs = set()
    for file_path in domain_files:
        base_name = os.path.basename(file_path)
        prefix = base_name.split('_')[0]
        runs.add(prefix)
    return sorted(list(runs))

def load_json_by_type(file_type, timestamp_prefix):
    pattern = os.path.join(INPUT_FOLDER, f"{timestamp_prefix}_{file_type}.json")
    files = glob.glob(pattern)
    if not files:
        return []
    with open(files[0], 'r') as f:
        data = json.load(f)
    return data.get("data", [])

def save_flags(flags, filename="flags.json"):
    path = os.path.join(OUTPUT_FOLDER, filename)
    with open(path, 'w') as f:
        json.dump(flags, f, indent=4)
    print(f"Flags saved to {path}")

# Vulnerability Number One: Excessive User Rights and Permissions
def check_excessive_permissions(users, flags, scan_prefix=None):
    dangerous_rights = [
        "GenericAll",
        "GenericWrite",
        "WriteDacl",
        "WriteOwner",
        "AllExtendedRights"
    ]

    for user in users:
        properties = user.get("Properties", {})
        username = properties.get("name", "UnknownUser")
        aces = user.get("Aces", [])

        found_rights = set()

        for ace in aces:
            right = ace.get("RightName")
            if right in dangerous_rights:
                found_rights.add(right)

        if found_rights:
            flag_entry = {
                "user": username,
                "vulnerability": "Excessive Permissions",
                "permissions": list(found_rights),
                "description": f"{username} has dangerous rights: {', '.join(found_rights)}"
            }
            if scan_prefix:
                flag_entry["scan_prefix"] = scan_prefix
            flags.append(flag_entry)

# Vulnerability Number Two: Weak Password Policies (AS-REP Roasting)
def check_asrep_roasting(users, flags, scan_prefix=None):
    for user in users:
        properties = user.get("Properties", {})
        username = properties.get("name", "UnknownUser")

        if properties.get("dontreqpreauth") == True:
            flag_entry = {
                "user": username,
                "vulnerability": "AS-REP Roasting",
                "description": f"{username} does not require Kerberos pre-authentication (AS-REP roastable)."
            }
            if scan_prefix:
                flag_entry["scan_prefix"] = scan_prefix
            flags.append(flag_entry)

# Vulnerability Number Three: Unconstrained Delegation (Users and Computers)
def check_unconstrained_delegation(users, computers, flags, scan_prefix=None):
    # Check users
    for user in users:
        properties = user.get("Properties", {})
        username = properties.get("name", "UnknownUser")

        if properties.get("unconstraineddelegation") == True:
            flag_entry = {
                "user": username,
                "vulnerability": "Unconstrained Delegation",
                "description": f"User {username} has unconstrained delegation enabled (high risk)."
            }
            if scan_prefix:
                flag_entry["scan_prefix"] = scan_prefix
            flags.append(flag_entry)

    # Check computers
    for computer in computers:
        properties = computer.get("Properties", {})
        comp_name = properties.get("name", "UnknownComputer")

        if properties.get("unconstraineddelegation") == True:
            flag_entry = {
                "computer": comp_name,
                "vulnerability": "Unconstrained Delegation",
                "description": f"Computer {comp_name} has unconstrained delegation enabled (high risk)."
            }
            if scan_prefix:
                flag_entry["scan_prefix"] = scan_prefix
            flags.append(flag_entry)
            
# Vulnerability Number Four: Kerberoastable Users
def check_kerberoastable_users(users, flags, scan_prefix=None):
    for user in users:
        properties = user.get("Properties", {})
        username = properties.get("name", "UnknownUser")

        if properties.get("hasspn") == True:
            flag_entry = {
                "user": username,
                "vulnerability": "Kerberoastable",
                "description": f"{username} has a Service Principal Name (SPN) set and is vulnerable to Kerberoasting."
            }
            if scan_prefix:
                flag_entry["scan_prefix"] = scan_prefix
            flags.append(flag_entry)

# Vulnerability Number Five: Machine Account Quota
def check_machine_account_quota(domains, flags, scan_prefix=None):
    for domain in domains:
        properties = domain.get("Properties", {})
        domain_name = properties.get("name", "UnknownDomain")

        quota = (
            properties.get("machineaccountquota")
            or properties.get("ms-DS-MachineAccountQuota")
            or properties.get("ms-ds-machineaccountquota")
            or 0
        )

        if quota > 0:
            flag_entry = {
                "domain": domain_name,
                "vulnerability": "Machine Account Quota",
                "quota": quota,
                "description": f"{domain_name} allows users to create {quota} machine accounts."
            }
            if scan_prefix:
                flag_entry["scan_prefix"] = scan_prefix
            flags.append(flag_entry)

# Vulnerability Number Six: Outdated OS
def check_outdated_os(computers, flags, scan_prefix=None):
    outdated_versions = [
        "Windows XP", "Windows Vista", "Windows 7", "Windows 8", "Windows 8.1",
        "Windows Server 2003", "Windows Server 2008", "Windows Server 2008 R2",
        "Windows Server 2012", "Windows Server 2012 R2", "Windows Server 2016",
        "Ubuntu 14", "Ubuntu 16", "CentOS 6", "CentOS 7"
    ]

    for computer in computers:
        props = computer.get("Properties", {})
        computer_name = props.get("name", "Unknown")
        domain_name = props.get("domain", "UnknownDomain")
        os_name = props.get("operatingsystem")

        if not os_name:
            continue

        for outdated in outdated_versions:
            if outdated in os_name:
                flag_entry = {
                    "computer": computer_name,
                    "domain": domain_name,
                    "vulnerability": "Outdated OS",
                    "operatingsystem": os_name,
                    "description": f"{computer_name} in {domain_name} is running an outdated OS: {os_name}"
                }
                if scan_prefix:
                    flag_entry["scan_prefix"] = scan_prefix
                flags.append(flag_entry)
                break

# Vulnerability Number Seven: DCSync Rights and Inheritance
def check_dcsync(domains, groups, users, flags, scan_prefix=None):
    admin_rids = ("-512", "-516", "-519", "-544")
    dangerous_group_rights = {"GenericAll", "GenericWrite", "WriteDacl", "WriteOwner", "Owns", "AddMember"}

    for domain in domains:
        sid_rights_map = {}
        aces = domain.get('Aces', [])
        
        for ace in aces:
            sid = ace.get('PrincipalSID') or ace.get('PrincipalId')
            right = ace.get('RightName') or ace.get('Right')
            p_type = ace.get('PrincipalType')
            
            if right in ("GetChanges", "GetChangesAll"):
                if sid not in sid_rights_map:
                    sid_rights_map[sid] = {"rights": set(), "type": p_type}
                sid_rights_map[sid]["rights"].add(right)
                
        for sid, info in sid_rights_map.items():
            if len(info["rights"]) == 2:
                if not any(sid.endswith(rid) for rid in admin_rids):
                    if info["type"] == "User":
                        target_user_name = sid
                        for user in users:
                            user_id = user.get('ObjectIdentifier', '')
                            u_props = user.get('Properties', {})
                            u_sid_prop = u_props.get('sid') or u_props.get('SID') or ''
                            
                            if (user_id == sid or user_id.endswith(sid) or sid.endswith(user_id) or 
                                u_sid_prop == sid or u_sid_prop.endswith(sid)):
                                target_user_name = u_props.get('name') or u_props.get('Name') or user_id or sid
                                break
                                
                        flag_entry = {
                            "principal": sid,
                            "target_name": target_user_name,
                            "vulnerability": "DCSync User Rights",
                            "description": f"User account '{target_user_name}' possesses direct DCSync rights over the domain."
                        }
                        if scan_prefix:
                            flag_entry["scan_prefix"] = scan_prefix
                        flags.append(flag_entry)

                    elif info["type"] == "Group":
                        target_group_name = sid
                        for group in groups:
                            group_id = group.get('ObjectIdentifier', '')
                            g_props = group.get('Properties', {})
                            g_sid_prop = g_props.get('sid') or g_props.get('SID') or ''
                            
                            if (group_id == sid or group_id.endswith(sid) or sid.endswith(group_id) or 
                                g_sid_prop == sid or g_sid_prop.endswith(sid)):
                                target_group_name = g_props.get('name') or g_props.get('Name') or group_id or sid
                                break
                        
                        flag_entry = {
                            "principal": sid,
                            "target_group": target_group_name,
                            "vulnerability": "DCSync Group Rights",
                            "description": f"Group '{target_group_name}' possesses direct DCSync rights over the domain."
                        }
                        if scan_prefix:
                            flag_entry["scan_prefix"] = scan_prefix
                        flags.append(flag_entry)
                        
                        for group in groups:
                            group_id = group.get('ObjectIdentifier', '')
                            if group_id == sid or group_id.endswith(sid) or sid.endswith(group_id):
                                members = group.get('Members', [])
                                for member in members:
                                    m_id = member.get('ObjectIdentifier')
                                    m_type = member.get('ObjectType')
                                    sub_entry = {
                                        "principal": m_id,
                                        "target_group": target_group_name,
                                        "vulnerability": "DCSync Inheritance",
                                        "description": f"Member '{m_id}' ({m_type}) inherits DCSync rights via group {target_group_name}."
                                    }
                                    if scan_prefix:
                                        sub_entry["scan_prefix"] = scan_prefix
                                    flags.append(sub_entry)
                                    
                                g_aces = group.get('Aces', [])
                                for g_ace in g_aces:
                                    ctrl_sid = g_ace.get('PrincipalSID')
                                    g_right = g_ace.get('RightName')
                                    if g_right in dangerous_group_rights:
                                        if not any(ctrl_sid.endswith(rid) for rid in admin_rids):
                                            hijack_entry = {
                                                "principal": ctrl_sid,
                                                "target_group": target_group_name,
                                                "vulnerability": "DCSync Group Hijack",
                                                "description": f"Principal '{ctrl_sid}' has '{g_right}' over DCSync group {target_group_name}."
                                            }
                                            if scan_prefix:
                                                hijack_entry["scan_prefix"] = scan_prefix
                                            flags.append(hijack_entry)

def main():
    os.makedirs(OUTPUT_FOLDER, exist_ok=True)
    # Prints a random SleuthHound banner at the top of the script output.
    import random
    def print_banner():
        banners = [
        r"""
 ____  _            _   _     _   _                       _ 
/ ___|| | ___ _   _| |_| |__ | | | | ___  _   _ _ __   __| |
\___ \| |/ _ \ | | | __| '_ \| |_| |/ _ \| | | | '_ \ / _` |
 ___) | |  __/ |_| | |_| | | |  _  | (_) | |_| | | | | (_| |
|____/|_|\___|\__,_|\__|_| |_|_| |_|\___/ \__,_|_| |_|\__,_|
        """,
        r"""
 __ _            _   _                                 _ 
/ _\ | ___ _   _| |_| |__   /\  /\___  _   _ _ __   __| |
\ \| |/ _ \ | | | __| '_ \ / /_/ / _ \| | | | '_ \ / _` |
_\ \ |  __/ |_| | |_| | | / __  / (_) | |_| | | | | (_| |
\__/_|\___|\__,_|\__|_| |_\/ /_/ \___/ \__,_|_| |_|\__,_|
        """,
        r"""
 ____ ____ ____ ____ ____ ____ ____ ____ ____ ____ ____ 
||S |||l |||e |||u |||t |||h |||H |||o |||u |||n |||d ||
||__|||__|||__|||__|||__|||__|||__|||__|||__|||__|||__||
|/__\|/__\|/__\|/__\|/__\|/__\|/__\|/__\|/__\|/__\|/__\|
        """,
        r"""
  █████████  ████                       █████    █████      █████   █████                                    █████
 ███░░░░░███░░███                      ░░███    ░░███      ░░███   ░░███                                    ░░███ 
░███    ░░░  ░███   ██████  █████ ████ ███████   ░███████   ░███    ░███   ██████  █████ ████ ████████    ███████ 
░░█████████  ░███  ███░░███░░███ ░███ ░░░███░    ░███░░███  ░███████████  ███░░███░░███ ░███ ░░███░░███  ███░░███ 
 ░░░░░░░░███ ░███ ░███████  ░███ ░███   ░███     ░███ ░███  ░███░░░░░███ ░███ ░███ ░███ ░███  ░███ ░███ ░███ ░███ 
 ███    ░███ ░███ ░███░░░   ░███ ░███   ░███ ███ ░███ ░███  ░███    ░███ ░███ ░███ ░███ ░███  ░███ ░███ ░███ ░███ 
░░█████████  █████░░██████  ░░████████  ░░█████  ████ █████ █████   █████░░██████  ░░████████ ████ █████░░████████
 ░░░░░░░░░  ░░░░░  ░░░░░░    ░░░░░░░░    ░░░░░  ░░░░ ░░░░░ ░░░░░   ░░░░░  ░░░░░░    ░░░░░░░░ ░░░░ ░░░░░  ░░░░░░░░ 
        """,
        r"""
 ######  ##       ######## ##     ## ######## ##     ## ##     ##  #######  ##     ## ##    ## ######## 
##    ## ##       ##       ##     ##    ##    ##     ## ##     ## ##     ## ##     ## ###   ## ##     ##
##       ##       ##       ##     ##    ##    ##     ## ##     ## ##     ## ##     ## ####  ## ##     ##
 ######  ##       ######   ##     ##    ##    ######### ######### ##     ## ##     ## ## ## ## ##     ##
      ## ##       ##       ##     ##    ##    ##     ## ##     ## ##     ## ##     ## ##  #### ##     ##
##    ## ##       ##       ##     ##    ##    ##     ## ##     ## ##     ## ##     ## ##   ### ##     ##
 ######  ######## ########  #######     ##    ##     ## ##     ##  #######   #######  ##    ## ######## 
        """,
        r"""
===============================================================================
==      ===  ======================  =====  ====  ==========================  =
=  ====  ==  ======================  =====  ====  ==========================  =
=  ====  ==  =================  ===  =====  ====  ==========================  =
==  =======  ===   ===  =  ==    ==  =====  ====  ===   ===  =  ==  = ======  =
====  =====  ==  =  ==  =  ===  ===    ===        ==     ==  =  ==     ===    =
======  ===  ==     ==  =  ===  ===  =  ==  ====  ==  =  ==  =  ==  =  ==  =  =
=  ====  ==  ==  =====  =  ===  ===  =  ==  ====  ==  =  ==  =  ==  =  ==  =  =
=  ====  ==  ==  =  ==  =  ===  ===  =  ==  ====  ==  =  ==  =  ==  =  ==  =  =
==      ===  ===   ====    ===   ==  =  ==  ====  ===   ====    ==  =  ===    =
===============================================================================
        """,
        r"""
_______        _______ _     _ _______ _     _ _     _  _____  _     _ __   _ ______ 
|______ |      |______ |     |    |    |_____| |_____| |     | |     | | \  | |     \
______| |_____ |______ |_____|    |    |     | |     | |_____| |_____| |  \_| |_____/
        """,
        """
 .-. .          .  .    .   .                  . 
(   )|         _|_ |    |   |                  | 
 `-. | .-. .  . |  |--. |---| .-. .  . .--. .-.| 
(   )|(.-' |  | |  |  | |   |(   )|  | |  |(   | 
 `-' `-`--'`--`-`-''  `-'   ' `-' `--`-'  `-`-'`-
        """,
        r"""
 o-o  o           o  o    o  o                  o
|     |           |  |    |  |                  |
 o-o  | o-o o  o -o- O--o O--O o-o o  o o-o   o-O
    | | |-' |  |  |  |  | |  | | | |  | |  | |  |
o--o  o o-o o--o  o  o  o o  o o-o o--o o  o  o-o
        """,
        r"""
  sss. d      d sss   d       b sss sssss d    d d    d   sSSSs   d       b d s  b d ss   
d      S      S       S       S     S     S    S S    S  S     S  S       S S  S S S   ~o 
Y      S      S       S       S     S     S    S S    S S       S S       S S   SS S     b
  ss.  S      S sSSs  S       S     S     S sSSS S sSSS S       S S       S S    S S     S
     b S      S       S       S     S     S    S S    S S       S S       S S    S S     P
     P S      S        S     S      S     S    S S    S  S     S   S     S  S    S S    S 
` ss'  P sSSs P sSSss   "sss"       P     P    P P    P   "sss"     "sss"   P    P P ss"  
        """,
        r"""
SleuthHound
        """,
        r"""
 S)ssss  l)L                    t)   h)      H)    hh                              d)
S)    ss  l)                  t)tTTT h)      H)    hh                              d)
 S)ss     l)  e)EEEEE u)   UU   t)   h)HHHH  H)hhhhhh  o)OOO  u)   UU n)NNNN   d)DDDD
     S)   l)  e)EEEE  u)   UU   t)   h)   HH H)    hh o)   OO u)   UU n)   NN d)   DD
S)    ss  l)  e)      u)   UU   t)   h)   HH H)    hh o)   OO u)   UU n)   NN d)   DD
 S)ssss  l)LL  e)EEEE  u)UUU    t)T  h)   HH H)    hh  o)OOO   u)UUU  n)   NN  d)DDDD
        """
        ]
        print(random.choice(banners))
        
    print_banner()

    scan_runs = get_scan_runs()
    if not scan_runs:
        raise FileNotFoundError("No valid domain files found in input folder.")

    excessive_flags = []
    asrep_flags = []
    delegation_flags = []
    kerberoast_flags = []
    machine_flags = []
    outdated_flags = []
    dcsync_flags = []

    for prefix in scan_runs:
        print(f"Processing scan run prefix: {prefix}")
        users = load_json_by_type("users", prefix)
        computers = load_json_by_type("computers", prefix)
        domains = load_json_by_type("domains", prefix)
        groups = load_json_by_type("groups", prefix)

        print(f"  -> Loaded {len(users)} users, {len(computers)} computers, {len(domains)} domains, {len(groups)} groups")
        
        check_excessive_permissions(users, excessive_flags, prefix)
        check_asrep_roasting(users, asrep_flags, prefix)
        check_unconstrained_delegation(users, computers, delegation_flags, prefix)
        check_kerberoastable_users(users, kerberoast_flags, prefix)
        check_machine_account_quota(domains, machine_flags, prefix)
        check_outdated_os(computers, outdated_flags, prefix)
        check_dcsync(domains, groups, users, dcsync_flags, prefix)

    all_flags = (
        excessive_flags + 
        asrep_flags + 
        delegation_flags + 
        kerberoast_flags + 
        machine_flags + 
        outdated_flags + 
        dcsync_flags
    )

    save_flags(excessive_flags, "excessive_permissions.json")
    save_flags(asrep_flags, "asrep_roasting.json")
    save_flags(delegation_flags, "unconstrained_delegation.json")
    save_flags(kerberoast_flags, "kerberoastable_users.json")
    save_flags(machine_flags, "machine_account_quota.json")
    save_flags(outdated_flags, "outdated_os.json")
    save_flags(dcsync_flags, "dcsync_abuse.json")

    save_flags(all_flags, "flags.json")
    
    print(f"Total vulnerabilities identified across all scans: {len(all_flags)}")

if __name__ == "__main__":
    main()
                      
```

</details>


---

## Disclaimer
SleuthHound is intended for authorized security auditing, educational research, and lawful operations only. Unauthorized access to computer systems is illegal. The developers of this tool do not condone or encourage any unlawful use of this script and are not responsible for any misuse or damage caused by this tool. Use responsibly and only on systems you have explicit permission to audit.
