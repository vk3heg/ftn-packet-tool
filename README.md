# FidoNet Packet Tool

A comprehensive utility for analyzing, repairing, and viewing FidoNet Type
2+ packet files.

**Version:** 1.6
**Author:** Stephen Walsh
**Contact:** vk3heg@gmail.com | FidoNet 3:633/280 | FSXNet 21:1/195 | Amiganet 39:901/280

## Table of Contents

- [Features](#features)
  - [Packet Analysis](#packet-analysis)
  - [Packet Repair](#packet-repair)
  - [Packet Modification](#packet-modification)
  - [Packet Information Viewing](#packet-information-viewing)
- [Usage](#usage)
  - [View Packet Information](#view-packet-information)
  - [Analyze Packet](#analyze-packet)
  - [Repair Packet](#repair-packet)
  - [Modify Packet Header](#modify-packet-header)
  - [Modify Message Fields](#modify-message-fields)
- [Command-Line Options](#command-line-options)
- [Packet Information Display](#packet-information-display)
  - [Header Information](#header-information)
  - [Message List](#message-list)
  - [Full Message View](#full-message-view)
- [Common Issues Fixed](#common-issues-fixed)
- [Product Code Lookup](#product-code-lookup)
- [File Handling](#file-handling)
  - [Backups](#backups)
  - [Output Files](#output-files)
- [Exit Codes](#exit-codes)
- [Requirements](#requirements)
- [Technical Details](#technical-details)
  - [FidoNet Type 2+ Packet Structure](#fidonet-type-2-packet-structure)
  - [Character Encoding](#character-encoding)
  - [Kludge Lines](#kludge-lines)
- [Examples](#examples)
- [Version](#version)
- [Author](#author)
- [License](#license)

## Features

### Packet Analysis
- Validates packet header structure
- Detects embedded null bytes in message text
- Identifies missing packet terminators
- Finds improperly terminated date fields
- Validates date field content
- Detects corrupted From/To name fields
- Detects corrupted Subject fields
- Detects incomplete message headers
- Reports structural issues

### Packet Repair
- Removes embedded null bytes from message text
- Fixes date fields without proper null terminators
- Validates and repairs invalid date fields
- Adds missing packet terminators (00 00)
- Truncates incomplete message headers
- Optionally clears packet passwords
- Creates backup files automatically

### Packet Modification
- Change packet header From/To addresses
- Change message From/To names
- Change message Subject fields
- Set or clear packet passwords
- Target specific messages or apply to all messages
- Combine multiple modifications in one operation

### Packet Information Viewing
- Display packet header information
- List all messages in a packet
- View individual messages with full body text
- Separate kludges from message body
- Product code lookup (automatically finds latest FTSCPROD.* file)

## Usage

### View Packet Information

```bash
# Show packet header only
./packet-tool.py -i packet.pkt

# Show packet header and message list
./packet-tool.py -i -m packet.pkt

# Show specific message with full body
./packet-tool.py -i -mn 1 --full packet.pkt
```

### Analyze Packet

```bash
# Check packet for issues without repairing
./packet-tool.py -a packet.pkt
```

Output shows:
- Packet validity status
- Number of messages found
- Embedded null locations
- Invalid date fields
- Invalid/corrupted From, To, and Subject fields
- Structural errors and warnings

### Repair Packet

```bash
# Repair packet (creates backup automatically)
./packet-tool.py packet.pkt

# Repair and specify output file
./packet-tool.py -o repaired.pkt packet.pkt

# Repair without creating backup
./packet-tool.py -nb packet.pkt

# Repair and clear password field
./packet-tool.py --cpw packet.pkt
```

### Modify Packet Header

```bash
# Correct From address in packet header
./packet-tool.py --cfa 2:234/567 packet.pkt

# Correct To address in packet header
./packet-tool.py --cta 3:633/280 packet.pkt

# Correct both addresses
./packet-tool.py --cfa 2:234/567 --cta 3:633/280 packet.pkt

# Set password (max 8 characters)
./packet-tool.py --spw secret packet.pkt

# Clear password
./packet-tool.py --cpw packet.pkt
```

### Modify Message Fields

```bash
# Correct From name in all messages
./packet-tool.py --cfn "Fred Smith" packet.pkt

# Correct To name in all messages
./packet-tool.py --ctn "All" packet.pkt

# Correct Subject in all messages
./packet-tool.py --cs "New Subject" packet.pkt

# Correct multiple fields at once in all messages
./packet-tool.py --cfn "Fred Smith" --ctn "All" --cs "New Subject" packet.pkt

# Correct fields only in specific messages (1-indexed)
./packet-tool.py --cfn "Fred Smith" --msg-nums 3,4 packet.pkt

# Correct multiple fields in specific messages
./packet-tool.py --cfn "Fred Smith" --ctn "All" --cs "New Subject" --msg-nums 1,2,3 packet.pkt
```

## Command-Line Options

```
positional arguments:
  input_file            Input packet file to process

optional arguments:
  -h, --help            Show help message and exit
  --version             Show program version and exit
  -o OUTPUT, --output OUTPUT
                        Output file (default: input + .repaired or .modified)
  -nb                   Don't create backup file
  -v, --verbose         Verbose output (debug level)
  -q, --quiet           Quiet mode, only errors

Information/Analysis:
  -i                    Display packet information
  -m                    Show message list (use with -i)
  -mn N                 Show specific message number (use with -i)
  --full                Show full message body (use with -mn)
  -a                    Analyze packet without repairing

Password Options:
  --cpw                 Clear password field in packet header
  --spw PASSWORD        Set password field in packet header (max 8 chars)

Modification Options:
  --cfa ADDRESS         Correct From address (format: zone:net/node)
  --cta ADDRESS         Correct To address (format: zone:net/node)
  --cfn NAME            Correct From name field in messages
  --ctn NAME            Correct To name field in messages
  --cs SUBJECT          Correct Subject field in messages
  --msg-nums N,N,...    Apply field changes only to specified messages
                        (comma-separated, 1-indexed)
```

## Packet Information Display

### Header Information
```
Packet: packet.pkt
Size: 1516 bytes

=== Packet Header ===
Dest. Node addr: 21:1/195.0
Orig. Node addr: 21:1/100.0
QDest Zone     : 21
QOrig Zone     : 21
Aux Net        : 0
Date           : 2025/10/08
Time           : 07:16:08
Pkt Type       : 2
ProdCode       : 4351 - HPT (DOS/OS2/Win32/Unix/BeOS)
Revision Major : 0
Revision Minor : 1
Password       :
Capability Word: 0001
Capability Val.: 0100
Product data   : 00000000
```

### Message List
```
=== Messages (1 total) ===

001 Orig.    : 1/100
    Dest.    : 1/195
    Attribute: 0000
    Cost     : 0
    Date     : 07 Oct 25  14:09:43
    To       : Mindsurfer
    From     : phigan
    Subject  : Re: file_id.diz - was IcyBoard 0.1.6 release
    Area     : FSX_BBS
```

### Full Message View
Shows message header, kludges (MSGID, REPLY, SEEN-BY, PATH, etc.), and body text separately.

## Common Issues Fixed

### 1. Embedded Null Bytes
FidoNet uses null bytes (0x00) as message terminators. NNTP messages may contain embedded
nulls that corrupt packet structure. The tool removes these while preserving message
integrity.

### 2. Date Field Issues
FidoNet date fields must be exactly 20 bytes (19 characters + null terminator).
Missing null terminators cause the parser to read into subsequent fields. The tool enforces
proper termination and validates date field content. Invalid date fields are replaced with
a placeholder date using the current date/time.

### 3. Missing Packet Terminators
Packets must end with 00 00. The tool adds missing terminators.

### 4. Incomplete Message Headers
Packets sometimes become truncated or corrupted, ending with an incomplete message header
 (< 14 bytes). This occurs when:
- Transmission is interrupted mid-packet
- File write is truncated
- Packet creation process fails mid-message

The tool detects incomplete headers, truncates the packet at the last complete message, and
adds a proper terminator. All complete messages are preserved intact.

**Example:**
```bash
# Before repair
$ ./packet-tool.py --analyze aaae8839.bad
Packet: aaae8839.bad
Size: 836 bytes
Errors:
  - Incomplete message header at 0x0341

# After repair
$ ./packet-tool.py aaae8839.bad
Status: repaired
Original size: 836 bytes
Repaired size: 835 bytes (1 byte removed)

$ ./packet-tool.py --analyze aaae8839.bad.repaired
Packet: aaae8839.bad.repaired
Size: 835 bytes
Valid: True
Messages: 1
(No errors!)
```

### 5. Password Management
The tool can set or clear passwords in packet headers:
- **Set password**: Use `--spw` to set a password (max 8 characters)
- **Clear password**: Use `--cpw` to remove an existing password for security

### 6. Field Validation
The tool validates message fields for corruption:
- **From/To names**: Detects excessive non-ASCII characters (>30% indicates corruption)
- **Subject fields**: Validates content and detects corruption patterns
- **Date fields**: Validates format and content
- **Note**: Corrupted fields are detected and reported but NOT auto-repaired.
  Use `--cfn`, `--ctn`, or `--cs` to manually correct them.

### 7. Address and Field Modifications
The tool can modify packet addresses and message fields:
- **Packet header addresses**: Correct originating or destination FidoNet addresses
   (zone:net/node format)
- **Message names**: Correct From or To names in message headers
- **Message subjects**: Correct Subject fields in messages
- **Selective targeting**: Apply changes to specific messages using `--msg-nums`
- **Backup creation**: Automatically creates `.bak` backups before modification
   (unless `-nb` is used)

## Product Code Lookup

The tool includes FTSC product code lookup using FTSCPROD files. It automatically finds and
uses the latest FTSCPROD.* file in the tool directory (e.g., FTSCPROD.020, FTSCPROD.021,
etc.). When displaying packet information, it shows the creating software name and platform:

```
ProdCode       : 4351 - HPT (DOS/OS2/Win32/Unix/BeOS)
```

Over 300 FidoNet product codes are recognized. The tool will use the newest FTSCPROD file
available, sorted by extension number and modification time.

## File Handling

### Backups
By default, the tool creates a backup file with `.bak` extension before repairing:
- `packet.pkt` → `packet.pkt.bak`

Use `-nb` to skip backup creation.

### Output Files
- Default: Overwrites input file (after creating backup)
- With `-o`: Writes to specified output file

## Exit Codes

- `0` - Success (packet clean or repaired successfully)
- `1` - Error or issues found

## Requirements

- Python 3.6 or later
- No external dependencies (uses standard library only)

## Technical Details

### FidoNet Type 2+ Packet Structure
- **Header**: 58 bytes
  - Node addresses (orig/dest)
  - Date/time
  - Packet type
  - Product code and revision
  - Password (8 bytes, offset 26-33)
  - Capability words

- **Messages**: Variable length
  - Message header (14 bytes)
  - Date, To, From, Subject (null-terminated strings)
  - Message text (null-terminated)

- **Terminator**: 00 00

### Character Encoding
Messages are decoded using CP437 (DOS) encoding, which is standard for FidoNet packets.

### Kludge Lines
Control information lines starting with 0x01 character:
- `MSGID`   - Message ID
- `REPLY`   - Reply to message ID
- `TZUTC`   - Timezone
- `PID`     - Program ID
- `TID`     - Tosser ID
- `SEEN-BY` - Routing information
- `PATH`    - Path taken

## Examples

```bash
# Show version
./packet-tool.py --version

# Check if packet needs repair
./packet-tool.py -a packet.pkt

# Repair packet with backup
./packet-tool.py packet.pkt

# View packet contents
./packet-tool.py -i -m packet.pkt

# Read specific message
./packet-tool.py -i -mn 1 --full packet.pkt

# Repair and remove password
./packet-tool.py --cpw packet.pkt

# Set password
./packet-tool.py --spw secret123 packet.pkt

# Repair to different file
./packet-tool.py -o clean.pkt packet.pkt

# Correct packet addresses
./packet-tool.py --cfa 2:234/567 --cta 3:633/280 packet.pkt

# Correct message fields in all messages
./packet-tool.py --cfn "Fred Smith" --ctn "All" --cs "Test Subject" packet.pkt

# Correct message fields in specific messages only
./packet-tool.py --cfn "Fred Smith" --msg-nums 1,3,5 packet.pkt

# Verbose mode for debugging
./packet-tool.py -v packet.pkt

# Quiet mode (errors only)
./packet-tool.py -q packet.pkt
```

## Version

Current version: 1.6.0

## Author

Created for PyGate FidoNet/NNTP gateway and other FTN Project's.

## License

MIT License - This tool is part of the PyGate project.
