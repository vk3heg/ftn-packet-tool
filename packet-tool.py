#!/usr/bin/env python3
"""
PyGate Packet Tool

Repairs FidoNet packets with the following issues:
1. Embedded null bytes in message text - Null bytes are used as message
   terminators in FidoNet, so embedded nulls in NNTP message bodies can
   corrupt packets.
2. Date fields without null terminators - FidoNet date fields must be
   exactly 20 bytes (19 characters + null terminator). Missing null
   terminators cause the parser to read into subsequent fields.
3. Missing packet terminators - Adds proper packet terminator (00 00)
   if missing.
4. Packet passwords - Can optionally clear password field in packet
   header for security.
5. Corrupted message fields - Can fix corrupted From, To, and Subject
   fields in message headers.

This utility scans packets for these issues and repairs them while
preserving the packet structure.
"""

__version__ = "1.6.0"
__author__ = "PyGate Project"
__license__ = "MIT"

import struct
import os
from typing import List, Dict, Optional, Tuple
import logging


class PacketRepairError(Exception):
    """Exception raised for packet repair errors"""
    pass


class PacketRepairer:
    """FidoNet packet repair utility"""

    def __init__(self, logger: Optional[logging.Logger] = None):
        self.logger = logger or logging.getLogger(__name__)
        self.product_codes = self._load_product_codes()

    def _load_product_codes(self) -> Dict[int, Dict[str, str]]:
        """
        Load FTSC product codes from FTSCPROD file (any extension)

        Returns:
            Dictionary mapping product code to product info
        """
        products = {}

        # Find FTSCPROD file with any extension
        base_dir = os.path.dirname(__file__) or '.'
        prod_file = None

        # Look for FTSCPROD.* files, use the newest one
        import glob
        prod_files = glob.glob(os.path.join(base_dir, 'FTSCPROD.*'))

        if prod_files:
            # Sort by extension number (higher = newer) then by
            # modification time
            prod_files.sort(
                key=lambda x: (os.path.splitext(x)[1],
                              os.path.getmtime(x)),
                reverse=True)
            prod_file = prod_files[0]
            self.logger.debug(
                f"Using product code file: {os.path.basename(prod_file)}")
        else:
            self.logger.debug(
                "No FTSCPROD file found, product names "
                "will not be available")
            return products

        if not os.path.exists(prod_file):
            return products

        try:
            with open(prod_file, 'r') as f:
                for line in f:
                    line = line.strip()
                    if not line or line.startswith('#'):
                        continue

                    parts = line.split(',')
                    if len(parts) >= 3:
                        try:
                            code = int(parts[0], 16)
                            name = parts[1]
                            platform = parts[2]
                            products[code] = {
                                'name': name,
                                'platform': platform
                            }
                        except ValueError:
                            continue
        except Exception as e:
            self.logger.debug(f"Error loading product codes: {e}")

        self.logger.debug(f"Loaded {len(products)} product codes")
        return products

    def get_product_name(self, prod_code: int) -> str:
        """
        Get product name from code

        Args:
            prod_code: Product code

        Returns:
            Product name or "Unknown" if not found
        """
        if prod_code in self.product_codes:
            info = self.product_codes[prod_code]
            return f"{info['name']} ({info['platform']})"
        return "Unknown"

    def read_null_string(self, data: bytes, pos: int,
                         max_len: int = None,
                         field_name: str = None
                         ) -> Tuple[bytes, int, bool]:
        """
        Read null-terminated string from data

        Args:
            data: Byte data to read from
            pos: Starting position
            max_len: Maximum field length (for FidoNet date field = 20)
            field_name: Field name for logging

        Returns:
            Tuple of (field_data, new_position, was_truncated)
        """
        result = bytearray()
        start_pos = pos
        truncated = False

        while pos < len(data) and data[pos] != 0:
            result.append(data[pos])
            pos += 1

            # Check if we've exceeded max length without finding
            # null terminator
            if max_len and (pos - start_pos) >= max_len:
                self.logger.warning(
                    f"Field '{field_name}' at {start_pos:#06x} "
                    f"exceeded max length {max_len} "
                    f"without null terminator")
                truncated = True
                # Don't increment pos - at position where null should be
                return (bytes(result[:max_len-1]),
                        start_pos + max_len,
                        truncated)

        if pos < len(data):
            pos += 1  # Skip the null terminator
        return bytes(result), pos, truncated

    def get_placeholder_date(self) -> bytes:
        """
        Generate a placeholder FidoNet date field using current date/time

        Returns:
            bytes: Current date in FidoNet format (19 bytes)
        """
        import datetime

        # Get current time
        now = datetime.datetime.now()

        # FidoNet date format: "DD Mon YY  HH:MM:SS" (19 bytes)
        # Month names in FidoNet format
        months = ['Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun',
                  'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec']

        date_str = (f"{now.day:02d} {months[now.month-1]} "
                    f"{now.year % 100:02d}  {now.hour:02d}:"
                    f"{now.minute:02d}:{now.second:02d}")

        return date_str.encode('ascii')

    def validate_date_field(self, date_bytes: bytes) -> Dict:
        """
        Validate FidoNet date field content

        Expected format: "DD Mon YY  HH:MM:SS" (19 bytes)
        Examples: "01 Jan 25  12:34:56", "31 Dec 24  23:59:59"

        Args:
            date_bytes: Date field bytes (without null terminator)

        Returns:
            dict with keys:
                - valid: bool
                - reason: str (if invalid)
        """
        result = {'valid': True, 'reason': None}

        # Check minimum length (should be 19 bytes for proper FidoNet date)
        if len(date_bytes) == 0:
            result['valid'] = False
            result['reason'] = "Empty date field"
            return result

        if len(date_bytes) < 10:
            result['valid'] = False
            result['reason'] = (f"Date too short ({len(date_bytes)} "
                                f"bytes, expected 19)")
            return result

        # Decode and check basic format
        try:
            date_str = date_bytes.decode('ascii', errors='replace')
        except:
            result['valid'] = False
            result['reason'] = "Date field contains non-ASCII characters"
            return result

        # Basic sanity check: should have spaces and colons
        if ' ' not in date_str or ':' not in date_str:
            result['valid'] = False
            result['reason'] = f"Invalid date format: '{date_str}'"
            return result

        return result

    def validate_name_field(self, field_bytes: bytes, field_name: str) -> Dict:
        """
        Validate FidoNet name field (To/From)

        Args:
            field_bytes: Field bytes (without null terminator)
            field_name: Name of the field ('to' or 'from')

        Returns:
            dict with keys:
                - valid: bool
                - reason: str (if invalid)
        """
        result = {'valid': True, 'reason': None}

        # Check if empty
        if len(field_bytes) == 0:
            result['valid'] = False
            result['reason'] = f"Empty {field_name} field"
            return result

        # Check for excessive length (> 36 bytes is unusual for FidoNet names)
        if len(field_bytes) > 36:
            result['valid'] = False
            result['reason'] = (f"{field_name.capitalize()} field too long "
                                f"({len(field_bytes)} bytes, max 36)")
            return result

        # Decode and check for control characters (except space and printable)
        try:
            name_str = field_bytes.decode('cp437', errors='replace')
        except:
            result['valid'] = False
            result['reason'] = f"{field_name.capitalize()} field decode error"
            return result

        # Check for invalid control characters (allow printable chars)
        for char in name_str:
            if ord(char) < 32 and char not in ['\r', '\n']:
                result['valid'] = False
                result['reason'] = (f"{field_name.capitalize()} field "
                                    f"contains control characters")
                return result

        # Check for excessive extended ASCII characters (possible corruption)
        # Count characters outside normal ASCII range (127+)
        extended_count = sum(1 for char in name_str if ord(char) > 127)
        # Strip leading/trailing spaces to get actual content
        stripped = name_str.strip()
        if stripped:
            # Calculate ratio based on stripped content
            extended_in_content = sum(
                1 for char in stripped if ord(char) > 127)
            content_ratio = extended_in_content / len(stripped)
            # Flag if >30% of actual content is extended ASCII
            if content_ratio > 0.3:
                result['valid'] = False
                result['reason'] = (f"{field_name.capitalize()} field "
                                    f"appears corrupted (excessive non-ASCII: "
                                    f"{content_ratio*100:.0f}%)")
                return result

        return result

    def validate_subject_field(self, subject_bytes: bytes) -> Dict:
        """
        Validate FidoNet subject field

        Args:
            subject_bytes: Subject field bytes (without null terminator)

        Returns:
            dict with keys:
                - valid: bool
                - reason: str (if invalid)
        """
        result = {'valid': True, 'reason': None}

        # Empty subject is technically valid
        if len(subject_bytes) == 0:
            return result

        # Check for excessive length (> 72 bytes is unusual for FidoNet
        # subjects)
        if len(subject_bytes) > 72:
            result['valid'] = False
            result['reason'] = (f"Subject field too long "
                                f"({len(subject_bytes)} bytes, max 72)")
            return result

        # Decode and check for control characters
        try:
            subject_str = subject_bytes.decode('cp437', errors='replace')
        except:
            result['valid'] = False
            result['reason'] = "Subject field decode error"
            return result

        # Check for invalid control characters (allow printable chars)
        for char in subject_str:
            if ord(char) < 32 and char not in ['\r', '\n']:
                result['valid'] = False
                result['reason'] = "Subject field contains control characters"
                return result

        # Check for excessive extended ASCII characters (possible corruption)
        # Count characters outside normal ASCII range (127+)
        extended_count = sum(1 for char in subject_str if ord(char) > 127)
        # Strip leading/trailing spaces to get actual content
        stripped = subject_str.strip()
        if stripped:
            # Calculate ratio based on stripped content
            extended_in_content = sum(
                1 for char in stripped if ord(char) > 127)
            content_ratio = extended_in_content / len(stripped)
            # Flag if >30% of actual content is extended ASCII
            if content_ratio > 0.3:
                result['valid'] = False
                pct = content_ratio * 100
                result['reason'] = (f"Subject field appears corrupted "
                                    f"(excessive non-ASCII: {pct:.0f}%)")
                return result

            # Also check if first 10 chars have >30% extended ASCII
            # (corrupted subjects often start with garbage)
            prefix = stripped[:min(10, len(stripped))]
            prefix_extended = sum(1 for char in prefix if ord(char) > 127)
            if len(prefix) >= 5 and prefix_extended / len(prefix) > 0.3:
                result['valid'] = False
                result['reason'] = (
                    f"Subject field appears corrupted "
                    f"(non-ASCII prefix: {prefix_extended}/{len(prefix)})")
                return result

        return result

    def validate_packet_header(self, packet_data: bytes) -> Dict:
        """
        Validate FidoNet packet header (58 bytes)

        Returns:
            dict with keys:
                - valid: bool
                - warnings: list of warning strings
        """
        result = {'valid': True, 'warnings': []}

        if len(packet_data) < 58:
            result['valid'] = False
            return result

        # Parse header fields for validation (using two-part format
        # like get_packet_info)
        try:
            # Part 1: bytes 0-33 (34 bytes)
            part1 = struct.unpack('<HHHHHHHHHHHHBB8s',
                                  packet_data[0:34])

            # Part 2: bytes 34-57 (24 bytes)
            part2 = struct.unpack('<HHHHBBHHHHHI',
                                  packet_data[34:58])

            # Check packet type (should be 2 or 2+)
            packet_type = part1[9]  # packet_type field
            # 0x2B = 2+, 0 also valid
            if packet_type not in [0, 2, 0x2B]:
                result['warnings'].append(
                    f"Unusual packet type: {packet_type:#04x}")

            # Validate zones if present
            qm_orig_zone = part2[0]  # qm_orig_zone
            qm_dest_zone = part2[1]  # qm_dest_zone
            if qm_orig_zone > 32767 or qm_dest_zone > 32767:
                result['warnings'].append(
                    f"Suspicious zone numbers: "
                    f"{qm_orig_zone}/{qm_dest_zone}")

        except struct.error as e:
            result['valid'] = False
            result['warnings'].append(f"Failed to parse packet header: {e}")

        return result

    def validate_message_header(self, header_data: bytes, pos: int) -> Dict:
        """
        Validate FidoNet message header (14 bytes)

        Returns:
            dict with keys:
                - valid: bool
                - version: int
                - warnings: list of warning strings
        """
        result = {'valid': True, 'version': 0, 'warnings': []}

        if len(header_data) < 14:
            result['valid'] = False
            result['warnings'].append(
                f"Message header too small at {pos:#06x}")
            return result

        try:
            (version, orig_node, dest_node,
             orig_net, dest_net, attrib, cost) = struct.unpack(
                '<HHHHHHH', header_data)
            result['version'] = version

            # Version should be 2 for Type 2 packets
            if version not in [0, 2]:
                result['warnings'].append(
                    f"Unusual message version {version:#04x} at {pos:#06x}")

            # Validate node/net numbers are reasonable
            if orig_node > 32767 or dest_node > 32767:
                result['warnings'].append(
                    f"Suspicious node numbers at {pos:#06x}: "
                    f"{orig_node}/{dest_node}")
            if orig_net > 32767 or dest_net > 32767:
                result['warnings'].append(
                    f"Suspicious net numbers at {pos:#06x}: "
                    f"{orig_net}/{dest_net}")

        except struct.error as e:
            result['valid'] = False
            result['warnings'].append(
                f"Failed to parse message header at {pos:#06x}: {e}")

        return result

    def analyze_packet(self, packet_data: bytes) -> Dict:
        """
        Analyze packet structure and find issues

        Returns:
            dict with keys:
                - valid: bool - whether packet structure is valid
                - messages: int - number of messages found
                - embedded_nulls: list of dicts with position info
                - oversized_dates: list of dicts with oversized date info
                - invalid_dates: list of dicts with invalid date info
                - invalid_from: list of dicts with invalid from field info
                - invalid_to: list of dicts with invalid to field info
                - invalid_subject: list of dicts with invalid subject info
                - errors: list of error strings
                - warnings: list of warning strings
                - missing_terminator: bool - whether packet lacks
                  proper terminator
        """
        result = {
            'valid': True,
            'messages': 0,
            'embedded_nulls': [],
            'oversized_dates': [],
            'invalid_dates': [],
            'invalid_from': [],
            'invalid_to': [],
            'invalid_subject': [],
            'errors': [],
            'warnings': [],
            'missing_terminator': False
        }

        if len(packet_data) < 58:
            result['valid'] = False
            result['errors'].append("Packet too small for header")
            return result

        # Validate packet header
        header_check = self.validate_packet_header(packet_data)
        if not header_check['valid']:
            result['valid'] = False
            result['errors'].append("Invalid packet header")
            return result
        result['warnings'].extend(header_check['warnings'])

        pos = 58  # Start after packet header

        while pos < len(packet_data) - 2:
            # Read and validate message header
            if pos + 14 > len(packet_data):
                result['errors'].append(
                    f"Incomplete message header at {pos:#06x}")
                break

            msg_header = packet_data[pos:pos+14]
            header_check = self.validate_message_header(msg_header, pos)

            if not header_check['valid']:
                result['errors'].append(
                    f"Invalid message header at {pos:#06x}")
                break

            result['warnings'].extend(header_check['warnings'])
            version = header_check['version']

            if version == 0:  # Packet terminator
                self.logger.debug(f"Found packet terminator at {pos:#06x}")
                break

            if version != 2:
                # This might be embedded nulls causing misalignment
                result['errors'].append(
                    f"Unexpected version {version:#04x} at position "
                    f"{pos:#06x}")
                break

            result['messages'] += 1
            message_start = pos
            self.logger.debug(
                f"Processing message {result['messages']} at {pos:#06x}")

            # Move past message header (14 bytes)
            pos += 14

            # Read 4 null-terminated strings (date, to, from, subject)
            for field_name in ['date', 'to', 'from', 'subject']:
                if pos >= len(packet_data):
                    result['errors'].append(
                        f"Unexpected EOF reading {field_name} in "
                        f"message {result['messages']}")
                    result['valid'] = False
                    return result

                # Date field max length: 20 bytes (19 chars + null)
                max_len = 20 if field_name == 'date' else None
                field_data, pos, truncated = self.read_null_string(
                    packet_data, pos, max_len, field_name)
                self.logger.debug(f"  {field_name}: {len(field_data)} bytes")

                # Track oversized date fields
                if field_name == 'date' and truncated:
                    result['oversized_dates'].append({
                        'message': result['messages'],
                        'position': pos - len(field_data) - 1
                    })

                # Validate date field content
                if field_name == 'date':
                    date_check = self.validate_date_field(field_data)
                    if not date_check['valid']:
                        result['invalid_dates'].append({
                            'message': result['messages'],
                            'position': pos - len(field_data) - 1,
                            'reason': date_check['reason'],
                            'content': field_data.decode(
                                'ascii', errors='replace')
                        })
                        result['warnings'].append(
                            f"Message {result['messages']}: "
                            f"{date_check['reason']}")

                # Validate to/from name fields
                elif field_name in ['to', 'from']:
                    name_check = self.validate_name_field(
                        field_data, field_name)
                    if not name_check['valid']:
                        invalid_list = (
                            result['invalid_to'] if field_name == 'to'
                                        else result['invalid_from'])
                        invalid_list.append({
                            'message': result['messages'],
                            'position': pos - len(field_data) - 1,
                            'reason': name_check['reason'],
                            'content': field_data.decode(
                                'cp437', errors='replace')
                        })
                        result['warnings'].append(
                            f"Message {result['messages']}: "
                            f"{name_check['reason']}")

                # Validate subject field
                elif field_name == 'subject':
                    subject_check = self.validate_subject_field(field_data)
                    if not subject_check['valid']:
                        result['invalid_subject'].append({
                            'message': result['messages'],
                            'position': pos - len(field_data) - 1,
                            'reason': subject_check['reason'],
                            'content': field_data.decode(
                                'cp437', errors='replace')
                        })
                        result['warnings'].append(
                            f"Message {result['messages']}: "
                            f"{subject_check['reason']}")

            # Now read message text, looking for embedded nulls
            text_start = pos

            while pos < len(packet_data):
                if packet_data[pos] == 0:
                    # Check if this is the real message terminator
                    is_terminator = False

                    if pos + 1 < len(packet_data):
                        next_byte = packet_data[pos + 1]
                        if next_byte == 0:  # 00 00 = packet terminator
                            is_terminator = True
                        elif pos + 2 < len(packet_data):
                            next_word = struct.unpack(
                                '<H', packet_data[pos+1:pos+3])[0]
                            # 00 02 00 = next message header
                            if next_word == 2:
                                is_terminator = True

                    if is_terminator:
                        self.logger.debug(
                            f"  Message text ends at {pos:#06x}")
                        pos += 1  # Move past the terminator
                        break
                    else:
                        # This is an embedded null
                        self.logger.warning(
                            f"  Found embedded null at {pos:#06x}")
                        result['embedded_nulls'].append({
                            'message': result['messages'],
                            'position': pos,
                            'text_offset': pos - text_start,
                            'context': bytes(packet_data[
                                max(0, pos-10):min(len(packet_data),
                                                    pos+10)])
                        })

                pos += 1

        # Check if packet has proper terminator (00 00)
        if pos >= len(packet_data) - 1:
            result['missing_terminator'] = True
            result['warnings'].append(
                "Packet may be missing terminator (00 00)")
        elif packet_data[pos:pos+2] != b'\x00\x00':
            result['missing_terminator'] = True
            result['warnings'].append(
                f"Packet terminator not found at expected position "
                f"{pos:#06x}")

        return result

    def get_packet_info(self, packet_data: bytes) -> Dict:
        """
        Extract packet header information

        Returns:
            dict with packet header information
        """
        if len(packet_data) < 58:
            return {'error': 'Packet too small for header'}

        try:
            # Parse packet header in two parts (58 bytes total)
            # Part 1: bytes 0-33 (34 bytes)
            part1 = struct.unpack('<HHHHHHHHHHHHBB8s', packet_data[0:34])

            # Part 2: bytes 34-57 (24 bytes)
            part2 = struct.unpack('<HHHHBBHHHHHI', packet_data[34:58])

            info = {
                'orig_node': part1[0],
                'dest_node': part1[1],
                'year': part1[2],
                'month': part1[3] + 1,  # Convert from 0-based to 1-based
                'day': part1[4],
                'hour': part1[5],
                'minute': part1[6],
                'second': part1[7],
                'baud': part1[8],
                'packet_type': part1[9],
                'orig_net': part1[10],
                'dest_net': part1[11],
                'prod_code_low': part1[12],
                'prod_revision': part1[13],
                'password': part1[14].decode(
                    'ascii', errors='replace').rstrip('\x00'),
                'qm_orig_zone': part2[0],
                'qm_dest_zone': part2[1],
                'aux_net': part2[2],
                'cap_valid': part2[3],
                'prod_code_high': part2[4],
                'prod_revision_minor': part2[5],
                'cap_word': part2[6],
                'orig_zone_dup': part2[7],
                'dest_zone_dup': part2[8],
                'orig_point': part2[9],
                'dest_point': part2[10],
                'extrainfo': part2[11]
            }

            # Calculate full product code
            info['prod_code'] = (part2[4] << 8) | part1[12]

            # Product data is stored in extrainfo (4 bytes)
            info['prod_data'] = f"{part2[11]:08x}"

            return info

        except Exception as e:
            return {'error': f'Failed to parse packet header: {e}'}

    def get_message_info(
        self,
        packet_data: bytes,
        message_num: int = None
        ) -> List[Dict]:
        """
        Extract message information from packet

        Args:
            packet_data: Packet data bytes
            message_num: If specified, return only that message number
            (1-indexed)

        Returns:
            list of message info dictionaries
        """
        messages = []
        pos = 58  # Start after packet header

        msg_count = 0
        while pos < len(packet_data) - 2:
            if pos + 14 > len(packet_data):
                break

            # Read message header (14 bytes)
            msg_header = packet_data[pos:pos+14]
            try:
                (version, orig_node, dest_node,
                 orig_net, dest_net, attrib, cost) = struct.unpack(
                    '<HHHHHHH', msg_header)
            except struct.error:
                break

            if version == 0:  # End of packet
                break

            if version != 2:
                break

            msg_count += 1

            # Skip if not the requested message
            if message_num is not None and msg_count != message_num:
                # Need to skip to next message - read through fields
                pos += 14
                for _ in range(4):  # date, to, from, subject
                    while pos < len(packet_data) and packet_data[pos] != 0:
                        pos += 1
                    pos += 1  # Skip null
                # Skip to message terminator
                while pos < len(packet_data) and packet_data[pos] != 0:
                    pos += 1
                pos += 1
                continue

            pos += 14

            # Read null-terminated fields
            msg_date, pos, _ = self.read_null_string(
                packet_data, pos, 20, 'date')
            msg_to, pos, _ = self.read_null_string(packet_data, pos)
            msg_from, pos, _ = self.read_null_string(packet_data, pos)
            msg_subject, pos, _ = self.read_null_string(packet_data, pos)

            # Read message text
            text_start = pos
            text_bytes = bytearray()
            while pos < len(packet_data):
                if packet_data[pos] == 0:
                    # Check if this is message terminator
                    if pos + 1 < len(packet_data):
                        next_byte = packet_data[pos + 1]
                        if next_byte == 0:  # Packet end
                            break
                        elif pos + 2 < len(packet_data):
                            next_word = struct.unpack(
                                '<H', packet_data[pos+1:pos+3])[0]
                            if next_word == 2:  # Next message
                                break
                text_bytes.append(packet_data[pos])
                pos += 1

            pos += 1  # Skip message terminator

            # Parse message text for area and kludges
            try:
                text = bytes(text_bytes).decode('cp437', errors='replace')
            except:
                text = bytes(text_bytes).decode('ascii', errors='replace')

            area = None
            kludges = []
            body_lines = []
            in_body = False

            # Split by both \r and \n to handle different line endings
            lines = text.replace('\r\n', '\r').replace('\n', '\r').split('\r')

            for line in lines:
                if not line:
                    continue

                # Check if line contains kludges (starts with \x01)
                if line.startswith('\x01'):
                    # May have multiple kludges on one line
                    parts = line.split('\x01')
                    for part in parts:
                        if part:
                            kludges.append(part.strip())
                elif line.startswith('AREA:'):
                    # Area line may have kludges appended without \r separator
                    if '\x01' in line:
                        # Split area from kludges
                        area_part, rest = line.split('\x01', 1)
                        area = area_part[5:].strip()
                        # Process remaining kludges
                        for kludge in rest.split('\x01'):
                            if kludge:
                                kludges.append(kludge.strip())
                    else:
                        area = line[5:].strip()
                elif line.startswith('SEEN-BY:') or line.startswith('PATH:'):
                    # Control lines
                    kludges.append(line)
                elif line.startswith('---') or line.startswith(' * Origin:'):
                    # Tearline or origin
                    kludges.append(line)
                else:
                    # Body text - but check for embedded kludges
                    if '\x01' in line and not in_body:
                        # Has kludges before body started
                        parts = line.split('\x01')
                        for i, part in enumerate(parts):
                            if i == 0 and part:
                                # First part might be body
                                if part.strip():
                                    body_lines.append(part)
                                    in_body = True
                            elif part:
                                kludges.append(part.strip())
                    else:
                        # Pure body text
                        if line.strip() or in_body:
                            body_lines.append(line)
                            in_body = True

            msg_info = {
                'number': msg_count,
                'orig_net': orig_net,
                'orig_node': orig_node,
                'dest_net': dest_net,
                'dest_node': dest_node,
                'attribute': attrib,
                'cost': cost,
                'date': msg_date.decode('ascii', errors='replace'),
                'to': msg_to.decode('cp437', errors='replace'),
                'from': msg_from.decode('cp437', errors='replace'),
                'subject': msg_subject.decode('cp437', errors='replace'),
                'area': area,
                'kludges': kludges,
                'body': '\n'.join(body_lines).strip(),
                'text_length': len(text_bytes)
            }

            messages.append(msg_info)

            if message_num is not None and msg_count == message_num:
                break

        return messages

    def clear_password(self, packet_data: bytes) -> bytes:
        """
        Clear password field in packet header

        The password field is at bytes 26-33 (8 bytes) in the FidoNet Type
        2+ packet header. This method replaces the password with null bytes.

        Args:
            packet_data: Original packet data as bytes

        Returns:
            Packet data with password cleared
        """
        if len(packet_data) < 58:
            self.logger.error("Packet too small to have valid header")
            return packet_data

        output = bytearray(packet_data)

        # Password field is at offset 26, length 8 bytes
        password_offset = 26
        password_length = 8

        # Check if password exists (not all nulls)
        current_password = output[
            password_offset:password_offset+password_length]
        if current_password != b'\x00' * password_length:
            pwd_str = current_password.decode(
                'ascii', errors='replace').rstrip(chr(0))
            self.logger.info(f"Clearing password: {pwd_str}")
            output[password_offset:password_offset+password_length] = (
                b'\x00' * password_length)
        else:
            self.logger.debug("No password set in packet")

        return bytes(output)

    def set_password(self, packet_data: bytes, password: str) -> bytes:
        """
        Set password field in packet header

        The password field is at bytes 26-33 (8 bytes) in the FidoNet Type
        2+ packet header. Passwords are null-terminated and padded with nulls.

        Args:
            packet_data: Original packet data as bytes
            password: Password to set (max 8 characters)

        Returns:
            Packet data with password set

        Raises:
            ValueError: If password is too long
        """
        if len(packet_data) < 58:
            self.logger.error("Packet too small to have valid header")
            return packet_data

        # Validate password length
        if len(password) > 8:
            raise ValueError(
                f"Password too long ({len(password)} chars, max 8)")

        output = bytearray(packet_data)

        # Password field is at offset 26, length 8 bytes
        password_offset = 26
        password_length = 8

        # Get current password for logging
        current_password = output[
            password_offset:password_offset+password_length]
        if current_password != b'\x00' * password_length:
            old_pwd = current_password.decode(
                'ascii', errors='replace').rstrip(chr(0))
            self.logger.info(f"Changing password: '{old_pwd}' -> '{password}'")
        else:
            self.logger.info(f"Setting password: '{password}'")

        # Encode password and pad with nulls
        pwd_bytes = password.encode('ascii', errors='replace')
        # Pad to 8 bytes with nulls
        pwd_padded = pwd_bytes + (b'\x00' * (password_length - len(pwd_bytes)))

        output[password_offset:password_offset+password_length] = pwd_padded

        return bytes(output)

    def parse_fidonet_address(self, address: str) -> Dict:
        """
        Parse a FidoNet address string

        Args:
            address: Address string in format "zone:net/node" or
                     "zone:net/node.point"

        Returns:
            dict with keys: zone, net, node, point

        Raises:
            ValueError: If address format is invalid
        """
        import re

        # Match zone:net/node or zone:net/node.point
        match = re.match(r'^(\d+):(\d+)/(\d+)(?:\.(\d+))?$', address.strip())
        if not match:
            raise ValueError(
                f"Invalid FidoNet address format: {address}. "
                f"Expected format: zone:net/node or zone:net/node.point")

        zone = int(match.group(1))
        net = int(match.group(2))
        node = int(match.group(3))
        point = int(match.group(4)) if match.group(4) else 0

        # Validate ranges
        if zone > 32767 or net > 32767 or node > 32767 or point > 32767:
            raise ValueError(f"Address values must be <= 32767: {address}")

        return {
            'zone': zone,
            'net': net,
            'node': node,
            'point': point
        }

    def change_from_address(
        self,
        packet_data: bytes,
        new_address: str
        ) -> bytes:
        """
        Change the originating address in packet header

        Args:
            packet_data: Original packet data as bytes
            new_address: New from address in format "zone:net/node"

        Returns:
            Packet data with updated from address

        Raises:
            ValueError: If address format is invalid
        """
        if len(packet_data) < 58:
            self.logger.error("Packet too small to have valid header")
            return packet_data

        addr = self.parse_fidonet_address(new_address)
        output = bytearray(packet_data)

        # Get current address for logging
        info = self.get_packet_info(packet_data)
        old_addr = (f"{info['qm_orig_zone']}:{info['orig_net']}/"
                    f"{info['orig_node']}.{info['orig_point']}")

        self.logger.info(
            f"Correcting from address: {old_addr} -> {new_address}")

        # Update packet header fields
        # orig_node at offset 0 (2 bytes)
        struct.pack_into('<H', output, 0, addr['node'])
        # orig_net at offset 20 (2 bytes)
        struct.pack_into('<H', output, 20, addr['net'])
        # qm_orig_zone at offset 34 (2 bytes)
        struct.pack_into('<H', output, 34, addr['zone'])
        # orig_zone_dup at offset 44 (2 bytes)
        struct.pack_into('<H', output, 44, addr['zone'])
        # orig_point at offset 48 (2 bytes)
        struct.pack_into('<H', output, 48, addr['point'])

        return bytes(output)

    def change_to_address(
        self,
        packet_data: bytes,
        new_address: str
        ) -> bytes:
        """
        Change the destination address in packet header

        Args:
            packet_data: Original packet data as bytes
            new_address: New to address in format "zone:net/node"

        Returns:
            Packet data with updated to address

        Raises:
            ValueError: If address format is invalid
        """
        if len(packet_data) < 58:
            self.logger.error("Packet too small to have valid header")
            return packet_data

        addr = self.parse_fidonet_address(new_address)
        output = bytearray(packet_data)

        # Get current address for logging
        info = self.get_packet_info(packet_data)
        old_addr = (f"{info['qm_dest_zone']}:{info['dest_net']}/"
                    f"{info['dest_node']}.{info['dest_point']}")

        self.logger.info(
            f"Correcting to address: {old_addr} -> {new_address}")

        # Update packet header fields
        # dest_node at offset 2 (2 bytes)
        struct.pack_into('<H', output, 2, addr['node'])
        # dest_net at offset 22 (2 bytes)
        struct.pack_into('<H', output, 22, addr['net'])
        # qm_dest_zone at offset 36 (2 bytes)
        struct.pack_into('<H', output, 36, addr['zone'])
        # dest_zone_dup at offset 46 (2 bytes)
        struct.pack_into('<H', output, 46, addr['zone'])
        # dest_point at offset 50 (2 bytes)
        struct.pack_into('<H', output, 50, addr['point'])

        return bytes(output)

    def change_message_fields(self, packet_data: bytes,
                             from_name: Optional[str] = None,
                             to_name: Optional[str] = None,
                             subject: Optional[str] = None,
                             message_nums: Optional[List[int]] = None
                             ) -> bytes:
        """
        Change From, To, and/or Subject fields in message headers

        Args:
            packet_data: Original packet data as bytes
            from_name: New from name (if None, not changed)
            to_name: New to name (if None, not changed)
            subject: New subject (if None, not changed)
            message_nums: List of message numbers to change (1-indexed).
            If None, change all messages.

        Returns:
            Packet data with updated fields

        Raises:
            PacketRepairError: If packet structure is invalid
        """
        if len(packet_data) < 58:
            self.logger.error("Packet too small to have valid header")
            return packet_data

        if not from_name and not to_name and not subject:
            self.logger.warning("No fields to change specified")
            return packet_data

        # Encode fields in cp437 (standard FidoNet encoding)
        from_name_bytes = from_name.encode('cp437') if from_name else None
        to_name_bytes = to_name.encode('cp437') if to_name else None
        subject_bytes = subject.encode('cp437') if subject else None

        # Rebuild packet with changed fields
        output = bytearray()
        output.extend(packet_data[0:58])  # Copy packet header

        pos = 58
        message_num = 0

        while pos < len(packet_data) - 2:
            # Read message version
            if pos + 2 > len(packet_data):
                break

            version = struct.unpack('<H', packet_data[pos:pos+2])[0]

            if version == 0:  # Packet terminator
                output.extend(b'\x00\x00')
                break

            if version != 2:
                break

            message_num += 1
            should_change = message_nums is None or message_num in message_nums

            # Copy message header (14 bytes)
            output.extend(packet_data[pos:pos+14])
            pos += 14

            # Process the 4 null-terminated strings (date, to, from, subject)
            for field_name in ['date', 'to', 'from', 'subject']:
                max_len = 20 if field_name == 'date' else None
                field_data, pos, _ = self.read_null_string(packet_data,
                                                    pos, max_len, field_name)

                # Replace field if requested
                if should_change:
                    if field_name == 'to' and to_name_bytes:
                        old_value = field_data.decode('cp437',
                                              errors='replace')
                        self.logger.info(
                            f"Message {message_num}: Correcting To: "
                            f"'{old_value}' -> '{to_name}'")
                        field_data = to_name_bytes
                    elif field_name == 'from' and from_name_bytes:
                        old_value = field_data.decode('cp437',
                                              errors='replace')
                        self.logger.info(
                            f"Message {message_num}: Correcting From: "
                            f"'{old_value}' -> '{from_name}'")
                        field_data = from_name_bytes
                    elif field_name == 'subject' and subject_bytes:
                        old_value = field_data.decode('cp437',
                                              errors='replace')
                        self.logger.info(
                            f"Message {message_num}: Correcting Subject: "
                            f"'{old_value}' -> '{subject}'")
                        field_data = subject_bytes

                output.extend(field_data)
                output.append(0)  # Null terminator

            # Copy message text until terminator
            while pos < len(packet_data):
                byte = packet_data[pos]
                pos += 1
                output.append(byte)

                if byte == 0:
                    # Check if this is the message terminator
                    if pos < len(packet_data):
                        next_byte = packet_data[pos]
                        if next_byte == 0:  # Packet end
                            break
                        elif pos + 1 < len(packet_data):
                            next_word = struct.unpack('<H',
                                                  packet_data[pos:pos+2])[0]
                            if next_word == 2:  # Next message
                                break

        # Ensure packet has proper terminator
        if len(output) < 2 or output[-2:] != b'\x00\x00':
            self.logger.debug("Adding packet terminator (00 00)")
            output.extend(b'\x00\x00')

        return bytes(output)

    def change_message_names(
                    self, packet_data: bytes, from_name: Optional[str] = None,
                    to_name: Optional[str] = None,
                    message_nums: Optional[List[int]] = None) -> bytes:
        """
        Change From and/or To name fields in message headers
        (backward compatibility wrapper)

        Args:
            packet_data: Original packet data as bytes
            from_name: New from name (if None, not changed)
            to_name: New to name (if None, not changed)
            message_nums: List of message numbers to change (1-indexed).
            If None, change all messages.

        Returns:
            Packet data with updated name fields
        """
        return self.change_message_fields(packet_data, from_name=from_name,
                                          to_name=to_name,
                                          message_nums=message_nums)

    def change_from_name(
        self,
        packet_data: bytes,
        new_name: str,
        message_nums: Optional[List[int]] = None
        ) -> bytes:
        """
        Change From name field in message headers

        Args:
            packet_data: Original packet data as bytes
            new_name: New from name
            message_nums: List of message numbers to change (1-indexed).
            If None, change all messages.

        Returns:
            Packet data with updated from name fields
        """
        return self.change_message_names(
            packet_data, from_name=new_name, message_nums=message_nums)

    def change_to_name(
        self,
        packet_data: bytes,
        new_name: str,
        message_nums: Optional[List[int]] = None
        ) -> bytes:
        """
        Change To name field in message headers

        Args:
            packet_data: Original packet data as bytes
            new_name: New to name
            message_nums: List of message numbers to change (1-indexed).
            If None, change all messages.

        Returns:
            Packet data with updated to name fields
        """
        return self.change_message_names(
            packet_data, to_name=new_name, message_nums=message_nums)

    def change_subject(
        self,
        packet_data: bytes,
        new_subject: str,
        message_nums: Optional[List[int]] = None
        ) -> bytes:
        """
        Change Subject field in message headers

        Args:
            packet_data: Original packet data as bytes
            new_subject: New subject
            message_nums: List of message numbers to change (1-indexed).
            If None, change all messages.

        Returns:
            Packet data with updated subject fields
        """
        return self.change_message_fields(
            packet_data, subject=new_subject, message_nums=message_nums)

    def repair_packet(
        self,
        packet_data: bytes,
        clear_password: bool = False
        ) -> bytes:
        """
        Repair FidoNet packet by fixing multiple issues:
        - Remove embedded null bytes from message text
        - Fix date fields without proper null terminators
        - Add missing packet terminators (00 00)
        - Validate packet and message headers
        - Optionally clear packet password

        Args:
            packet_data: Original packet data as bytes
            clear_password: If True, clear password field in header

        Returns:
            Repaired packet data as bytes

        Raises:
            PacketRepairError: If packet structure is invalid
        """
        # Clear password first if requested
        if clear_password:
            packet_data = self.clear_password(packet_data)
        # Analyze first
        analysis = self.analyze_packet(packet_data)

        if not analysis['valid']:
            raise PacketRepairError(
                  f"Invalid packet structure: {'; '.join(analysis['errors'])}")

        # Check if there's anything to repair
        needs_repair = (analysis['embedded_nulls'] or
                        analysis['missing_terminator'] or
                        analysis['oversized_dates'] or
                        analysis['invalid_dates'] or
                        analysis['invalid_subject'] or
                        analysis['invalid_from'] or
                        analysis['invalid_to'])

        if not needs_repair:
            self.logger.info("No issues found, packet is clean")
            # Log warnings if any
            for warning in analysis['warnings']:
                self.logger.warning(warning)
            return packet_data

        if analysis['embedded_nulls']:
            self.logger.info(
                f"Found {len(analysis['embedded_nulls'])} embedded null(s) "
                f"to repair")
        if analysis['missing_terminator']:
            self.logger.info(
                "Missing or invalid packet terminator - "
                "will add proper terminator")
        if analysis['oversized_dates']:
            self.logger.info(
                f"Found {len(analysis['oversized_dates'])} oversized date "
                f"field(s) to repair")
        if analysis['invalid_dates']:
            self.logger.info(
                f"Found {len(analysis['invalid_dates'])} invalid date "
                f"field(s) to repair")
            for invalid_date in analysis['invalid_dates']:
                self.logger.warning(
                    f"  Message {invalid_date['message']}: "
                    f"{invalid_date['reason']} - '{invalid_date['content']}'")
        if analysis['invalid_from']:
            self.logger.info(
                f"Found {len(analysis['invalid_from'])} invalid from "
                f"field(s)")
            for invalid_from in analysis['invalid_from']:
                self.logger.warning(
                    f"  Message {invalid_from['message']}: "
                    f"{invalid_from['reason']} - '{invalid_from['content']}'")
        if analysis['invalid_to']:
            self.logger.info(
                f"Found {len(analysis['invalid_to'])} invalid to "
                f"field(s)")
            for invalid_to in analysis['invalid_to']:
                self.logger.warning(
                    f"  Message {invalid_to['message']}: "
                    f"{invalid_to['reason']} - '{invalid_to['content']}'")
        if analysis['invalid_subject']:
            self.logger.info(
                f"Found {len(analysis['invalid_subject'])} invalid subject "
                f"field(s)")
            for invalid_subject in analysis['invalid_subject']:
                self.logger.warning(
                    f"  Message {invalid_subject['message']}: "
                    f"{invalid_subject['reason']} - "
                    f"'{invalid_subject['content']}'")

        # Rebuild packet without embedded nulls
        output = bytearray()
        output.extend(packet_data[0:58])  # Copy packet header

        pos = 58
        message_num = 0

        while pos < len(packet_data) - 2:
            # Read message version
            if pos + 2 > len(packet_data):
                break

            version = struct.unpack('<H', packet_data[pos:pos+2])[0]

            if version == 0:  # Packet terminator
                output.extend(b'\x00\x00')
                break

            if version != 2:
                break

            message_num += 1

            # Copy message header (14 bytes)
            output.extend(packet_data[pos:pos+14])
            pos += 14

            # Copy the 4 null-terminated strings
            for field_name in ['date', 'to', 'from', 'subject']:
                # Date field has max length of 20 bytes (19 chars + null)
                max_len = 20 if field_name == 'date' else None
                field_data, pos, _ = self.read_null_string(packet_data,
                                                pos, max_len, field_name)

                # Fix invalid date fields (only dates are auto-repaired)
                if field_name == 'date':
                    date_check = self.validate_date_field(field_data)
                    if not date_check['valid']:
                        new_date = self.get_placeholder_date()
                        self.logger.info(
                        f"  Replacing invalid date in message "
                        f"{message_num}: "
                        f"'{field_data.decode('ascii', errors='replace')}' -> "
                        f"'{new_date.decode('ascii')}'")
                        field_data = new_date

                # Note: from/to/subject fields are NOT auto-repaired
                # User must use --cfn, --ctn, or --cs to fix them manually

                output.extend(field_data)
                output.append(0)  # Null terminator

            # Read message text and filter out embedded nulls
            text_data = bytearray()

            while pos < len(packet_data):
                byte = packet_data[pos]
                pos += 1

                if byte == 0:
                    # Check if this is the message terminator
                    is_terminator = False

                    if pos < len(packet_data):
                        next_byte = packet_data[pos]
                        if next_byte == 0:  # Packet end
                            is_terminator = True
                        elif pos + 1 < len(packet_data):
                            next_word = struct.unpack('<H',
                                                   packet_data[pos:pos+2])[0]
                            if next_word == 2:  # Next message
                                is_terminator = True

                    if is_terminator:
                        # Real terminator - write text and terminator
                        output.extend(text_data)
                        output.append(0)
                        break
                    else:
                        # Embedded null - skip it
                        self.logger.debug(
                            f"Skipping embedded null in message "
                            f"{message_num} at position {pos-1:#06x}")
                        continue

                text_data.append(byte)

        # Ensure packet has proper terminator
        if len(output) < 2 or output[-2:] != b'\x00\x00':
            self.logger.debug("Adding packet terminator (00 00)")
            output.extend(b'\x00\x00')

        return bytes(output)

    def repair_file(
        self,
        input_path: str,
        output_path: Optional[str] = None,
        backup: bool = True,
        clear_password: bool = False
        ) -> Dict:
        """
        Repair a FidoNet packet file

        Args:
            input_path: Path to packet file to repair
            output_path: Path for repaired file (default: input_path
            with .repaired extension)
            backup: Whether to create backup of original file
            clear_password: Whether to clear password field in header

        Returns:
            dict with repair statistics
        """
        if not os.path.exists(input_path):
            raise PacketRepairError(f"Input file not found: {input_path}")

        # Read original packet
        with open(input_path, 'rb') as f:
            original_data = f.read()

        original_size = len(original_data)
        self.logger.info(f"Read {original_size} bytes from {input_path}")

        # Analyze first
        analysis = self.analyze_packet(original_data)

        # Repair
        repaired_data = self.repair_packet(original_data,
                                           clear_password=clear_password)
        repaired_size = len(repaired_data)

        # Determine output path
        if output_path is None:
            if analysis['embedded_nulls']:
                # Has issues, use .repaired extension
                output_path = input_path + '.repaired'
            else:
                # Clean packet, no output needed
                return {
                    'input_file': input_path,
                    'original_size': original_size,
                    'repaired_size': repaired_size,
                    'messages': analysis['messages'],
                    'embedded_nulls': len(analysis['embedded_nulls']),
                    'bytes_removed': 0,
                    'status': 'clean'
                }

        # Create backup if requested
        if backup and os.path.exists(input_path):
            backup_path = input_path + '.bak'
            with open(backup_path, 'wb') as f:
                f.write(original_data)
            self.logger.info(f"Created backup: {backup_path}")

        # Write repaired packet
        with open(output_path, 'wb') as f:
            f.write(repaired_data)

        result = {
            'input_file': input_path,
            'output_file': output_path,
            'original_size': original_size,
            'repaired_size': repaired_size,
            'messages': analysis['messages'],
            'embedded_nulls': len(analysis['embedded_nulls']),
            'bytes_removed': original_size - repaired_size,
            'status': 'repaired'
        }

        self.logger.info(f"Repaired packet written to {output_path}")
        self.logger.info(
                   f"Removed {result['bytes_removed']} "
                   f"embedded null byte(s)")
        return result


def main():
    """Command-line interface for packet repair"""
    import argparse

    parser = argparse.ArgumentParser(
        description='Repair FidoNet packets',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
# View packet information        # View packet with message details
packet-tool.py -i badfile.pkt    packet-tool.py -i -m badfile.pkt

# Analyze a packet               # View specific message
packet-tool.py -a badfile.pkt    packet-tool.py -i -m 2 badfile.pkt

# Repair a packet                # Clear password
packet-tool.py badfile.pkt       packet-tool.py --cpw badfile.pkt

# Set password
packet-tool.py --spw secret123 badfile.pkt

# Repair without backup          # Specify output file
packet-tool.py -nb badfile.pkt   packet-tool.py badfile.pkt -o fixed.pkt

# Correct from address
packet-tool.py --cfa 2:234/567 myfile.pkt

# Correct to address
packet-tool.py --cta 3:633/280 myfile.pkt

# Correct from name in all messages
%(prog)s --cfn "Fred Smith" myfile.pkt

# Correct to name in all messages
%(prog)s --ctn "All" myfile.pkt

# Correct names only in messages 3 and 4
%(prog)s --cfn "Fred Smith" --ctn "All" --msg-nums 3,4 myfile.pkt

# Correct subject in messages 3 and 4
%(prog)s --cs "Files arrived at my BBS" --msg-nums 3,4 myfile.pkt

# Correct all fields at once
%(prog)s --cfn "Fred Smith" --ctn "All" --cs "Files arrived at my BBS"
         --msg-nums 3,4 myfile.pkt
        """
    )

    parser.add_argument('--version', action='version',
                        version=f'%(prog)s {__version__}')
    parser.add_argument('input_file', help='Input packet file')
    parser.add_argument('-o', '--output',
                        help='Output file (default: input + .repaired)')
    parser.add_argument('-i', action='store_true', dest='info',
                        help='Display packet information')
    parser.add_argument('-m', action='store_true', dest='messages',
                        help='Show message summaries (with -i)')
    parser.add_argument('-mn', type=int, metavar='N', dest='message',
                        help='Show specific message number (with -i)')
    parser.add_argument('--full', action='store_true',
                        help='Show full message body (with -mn)')
    parser.add_argument('-a', action='store_true', dest='analyze',
                        help='Only analyze, do not repair')
    parser.add_argument('-nb', action='store_true', dest='no_backup',
                        help='Do not create backup file')
    parser.add_argument('--cpw', action='store_true', dest='clear_password',
                        help='Clear password field in packet header')
    parser.add_argument('--spw', dest='set_password', metavar='PASSWORD',
                        help='Set password field in packet header '
                             '(max 8 chars)')
    parser.add_argument('--cfa', dest='change_from_address', metavar='ADDRESS',
                        help='Correct the Fidonet from address '
                             '(format: zone:net/node)')
    parser.add_argument('--cta', dest='change_to_address', metavar='ADDRESS',
                        help='Correct the Fidonet to address '
                             '(format: zone:net/node)')
    parser.add_argument('--cfn', dest='change_from_name', metavar='NAME',
                        help='Correct the From name field in messages')
    parser.add_argument('--ctn', dest='change_to_name', metavar='NAME',
                        help='Correct the To name field in messages')
    parser.add_argument('--cs', dest='change_subject', metavar='SUBJECT',
                        help='Correct the Subject field in messages')
    parser.add_argument('--msg-nums', dest='message_list',
                        metavar='N,N,...',
                        help='Apply field changes only to specified '
                             'message numbers (comma-separated, 1-indexed)')
    parser.add_argument('-v', '--verbose', action='store_true',
                        help='Verbose output')
    parser.add_argument('-q', '--quiet', action='store_true',
                        help='Quiet mode, only errors')

    args = parser.parse_args()

    # Setup logging
    log_level = logging.INFO
    if args.verbose:
        log_level = logging.DEBUG
    elif args.quiet:
        log_level = logging.ERROR

    logging.basicConfig(
        level=log_level,
        format='%(asctime)s - %(levelname)s - %(message)s',
        datefmt='%d-%b-%y %H:%M:%S'
    )

    logger = logging.getLogger(__name__)
    repairer = PacketRepairer(logger)

    try:
        if args.info:
            # Display packet information
            with open(args.input_file, 'rb') as f:
                packet_data = f.read()

            pkt_info = repairer.get_packet_info(packet_data)

            if 'error' in pkt_info:
                print(f"Error: {pkt_info['error']}")
                return 1

            # Display packet header
            print(f"Packet: {args.input_file}")
            print(f"Size: {len(packet_data)} bytes")
            print()
            print("=== Packet Header ===")
            print(f"Dest. Node addr: {pkt_info['qm_dest_zone']}:"
                  f"{pkt_info['dest_net']}/{pkt_info['dest_node']}.0")
            print(f"Orig. Node addr: {pkt_info['qm_orig_zone']}:"
                  f"{pkt_info['orig_net']}/{pkt_info['orig_node']}.0")
            print(f"QDest Zone     : {pkt_info['qm_dest_zone']}")
            print(f"QOrig Zone     : {pkt_info['qm_orig_zone']}")
            print(f"Aux Net        : {pkt_info['aux_net']}")
            print(f"Date           : {pkt_info['year']:04d}/"
                  f"{pkt_info['month']:02d}/{pkt_info['day']:02d}")
            print(f"Time           : {pkt_info['hour']:02d}:"
                  f"{pkt_info['minute']:02d}:{pkt_info['second']:02d}")
            print(f"Pkt Type       : {pkt_info['packet_type']}")
            prod_name = repairer.get_product_name(pkt_info['prod_code'])
            print(f"ProdCode       : {pkt_info['prod_code']} - {prod_name}")
            print(f"Revision Major : {pkt_info['prod_revision'] >> 4}")
            print(f"Revision Minor : {pkt_info['prod_revision'] & 0x0F}")
            print(f"Password       : {pkt_info['password']}")
            print(f"Capability Word: {pkt_info['cap_word']:04x}")
            print(f"Capability Val.: {pkt_info['cap_valid']:04x}")
            print(f"Product data   : {pkt_info['prod_data']}")

            # Get message info if requested
            if args.message is not None:
                # Show specific message
                messages = repairer.get_message_info(packet_data, args.message)
                if not messages:
                    print(f"\nMessage {args.message} not found")
                    return 1

                msg = messages[0]
                print(f"\n=== Message {msg['number']:03d} ===")
                print(f"Orig.    : {msg['orig_net']}/{msg['orig_node']}")
                print(f"Dest.    : {msg['dest_net']}/{msg['dest_node']}")
                print(f"Attribute: {msg['attribute']:04x}")
                print(f"Cost     : {msg['cost']}")
                print(f"Date     : {msg['date']}")
                print(f"To       : {msg['to']}")
                print(f"From     : {msg['from']}")
                print(f"Subject  : {msg['subject']}")
                if msg['area']:
                    print(f"Area     : {msg['area']}")

                if args.full:
                    print()
                    if msg['kludges']:
                        print("--- Kludges ---")
                        for kludge in msg['kludges']:
                            print(f"  {kludge}")
                        print()
                    print("--- Message Body ---")
                    print(msg['body'])
                    print()
                    print(f"--- End ({msg['text_length']} bytes) ---")

            elif args.messages:
                # Show all messages summary
                messages = repairer.get_message_info(packet_data)
                print(f"\n=== Messages ({len(messages)} total) ===")
                for msg in messages:
                    # Clean up fields for display - remove control
                    # characters that could mess up formatting
                    date_str = msg['date'].replace('\r', ' ').replace('\n',
                                                   ' ')
                    to_str = msg['to'].replace('\r', ' ').replace('\n', ' ')
                    from_str = msg['from'].replace('\r', ' ').replace('\n',
                                                   ' ')
                    subject_str = msg['subject'].replace('\r',
                                            ' ').replace('\n', ' ')

                    print(
                        f"\n{msg['number']:03d} Orig.    : "
                        f"{msg['orig_net']}/{msg['orig_node']}")
                    print(
                        f"    Dest.    : "
                        f"{msg['dest_net']}/{msg['dest_node']}")
                    print(f"    Attribute: {msg['attribute']:04x}")
                    print(f"    Cost     : {msg['cost']}")
                    print(f"    Date     : {date_str}")
                    print(f"    To       : {to_str}")
                    print(f"    From     : {from_str}")
                    print(f"    Subject  : {subject_str}")
                    if msg['area']:
                        print(f"    Area     : {msg['area']}")

            return 0

        elif args.analyze:
            # Analyze only
            with open(args.input_file, 'rb') as f:
                packet_data = f.read()

            analysis = repairer.analyze_packet(packet_data)

            print(f"Packet: {args.input_file}")
            print(f"Size: {len(packet_data)} bytes")
            print(f"Valid: {analysis['valid']}")
            print(f"Messages: {analysis['messages']}")
            print(f"Embedded nulls: {len(analysis['embedded_nulls'])}")
            print(f"Invalid dates: {len(analysis['invalid_dates'])}")
            print(f"Oversized dates: {len(analysis['oversized_dates'])}")
            print(f"Invalid from fields: {len(analysis['invalid_from'])}")
            print(f"Invalid to fields: {len(analysis['invalid_to'])}")
            print(f"Invalid subject fields: {len(analysis['invalid_subject'])}")

            if analysis['errors']:
                print("\nErrors:")
                for error in analysis['errors']:
                    print(f"  - {error}")

            if analysis['warnings']:
                print("\nWarnings:")
                for warning in analysis['warnings']:
                    print(f"  - {warning}")

            if analysis['embedded_nulls']:
                print("\nEmbedded null locations:")
                for null in analysis['embedded_nulls']:
                    print(
                         f"  Message {null['message']}, "
                         f"position {null['position']:#06x}")
                    print(f"    Context: {null['context'].hex(' ')}")

            if analysis['invalid_dates']:
                print("\nInvalid date fields:")
                for invalid_date in analysis['invalid_dates']:
                    print(
                         f"  Message {invalid_date['message']}: "
                         f"{invalid_date['reason']}")
                    print(f"    Content: '{invalid_date['content']}'")

            if analysis['invalid_from']:
                print("\nInvalid from fields:")
                for invalid_from in analysis['invalid_from']:
                    print(
                         f"  Message {invalid_from['message']}: "
                         f"{invalid_from['reason']}")
                    print(f"    Content: '{invalid_from['content']}'")

            if analysis['invalid_to']:
                print("\nInvalid to fields:")
                for invalid_to in analysis['invalid_to']:
                    print(
                         f"  Message {invalid_to['message']}: "
                         f"{invalid_to['reason']}")
                    print(f"    Content: '{invalid_to['content']}'")

            if analysis['invalid_subject']:
                print("\nInvalid subject fields:")
                for invalid_subject in analysis['invalid_subject']:
                    print(
                         f"  Message {invalid_subject['message']}: "
                         f"{invalid_subject['reason']}")
                    print(f"    Content: '{invalid_subject['content']}'")

            has_issues = (analysis['embedded_nulls'] or
                          analysis['invalid_dates'] or
                          analysis['oversized_dates'] or
                          analysis['invalid_from'] or
                          analysis['invalid_to'] or
                          analysis['invalid_subject'])
            return 0 if analysis['valid'] and not has_issues else 1

        else:
           # Check if we need to change addresses, message fields, or password
            if (args.change_from_address or args.change_to_address or
                    args.change_from_name or args.change_to_name or
                    args.change_subject or args.set_password):
                # Read packet
                with open(args.input_file, 'rb') as f:
                    packet_data = f.read()

                # Apply password change first if requested
                try:
                    if args.set_password:
                        packet_data = repairer.set_password(
                            packet_data, args.set_password)

                    # Apply address changes
                    if args.change_from_address:
                        packet_data = repairer.change_from_address(
                                      packet_data, args.change_from_address)

                    if args.change_to_address:
                        packet_data = repairer.change_to_address(
                                      packet_data, args.change_to_address)

                    # Apply message field changes
                    if (args.change_from_name or args.change_to_name or
                            args.change_subject):
                        # Parse message list if provided
                        message_nums = None
                        if args.message_list:
                            try:
                                message_nums = [
                                    int(n.strip())
                                    for n in args.message_list.split(',')]
                            except ValueError:
                                logger.error(
                                      f"Invalid message list format: "
                                      f"{args.message_list}")
                                return 1

                        # Use the unified change_message_fields method if
                        # multiple fields are being changed
                        if ((args.change_from_name or args.change_to_name) and
                                 args.change_subject):
                            packet_data = repairer.change_message_fields(
                                packet_data, from_name=args.change_from_name,
                                to_name=args.change_to_name,
                                subject=args.change_subject,
                                message_nums=message_nums)

                        elif args.change_from_name and args.change_to_name:
                            # Change both names at once
                            packet_data = repairer.change_message_names(
                                packet_data, from_name=args.change_from_name,
                                to_name=args.change_to_name,
                                message_nums=message_nums)
                        elif args.change_from_name:
                            packet_data = repairer.change_from_name(
                                packet_data, args.change_from_name,
                                message_nums)
                        elif args.change_to_name:
                            packet_data = repairer.change_to_name(
                                packet_data, args.change_to_name,
                                message_nums)
                        elif args.change_subject:
                            packet_data = repairer.change_subject(
                                packet_data, args.change_subject,
                                message_nums)

                    # Determine output path
                    output_path = (args.output if args.output
                                   else args.input_file + '.modified')

                    # Create backup if requested
                    if not args.no_backup:
                        backup_path = args.input_file + '.bak'
                        with (open(args.input_file, 'rb') as f_in,
                              open(backup_path, 'wb') as f_out):
                            f_out.write(f_in.read())
                        logger.info(f"Created backup: {backup_path}")

                    # Write modified packet
                    with open(output_path, 'wb') as f:
                        f.write(packet_data)

                    print(f"Status: modified")
                    print(f"Output: {output_path}")

                    return 0

                except ValueError as e:
                    logger.error(str(e))
                    return 1
            else:
                # Repair
                result = repairer.repair_file(
                    args.input_file,
                    args.output,
                    backup=not args.no_backup,
                    clear_password=args.clear_password
                )

                print(f"Status: {result['status']}")
                print(f"Messages: {result['messages']}")
                print(f"Original size: {result['original_size']} bytes")
                print(f"Repaired size: {result['repaired_size']} bytes")

                if result['bytes_removed'] > 0:
                    print(
                        f"Removed: {result['bytes_removed']} "
                        f"embedded null byte(s)")
                    print(f"Output: {result['output_file']}")

                return 0

    except PacketRepairError as e:
        logger.error(str(e))
        return 1
    except Exception as e:
        logger.error(f"Unexpected error: {e}")
        if args.verbose:
            import traceback
            traceback.print_exc()
        return 1


if __name__ == '__main__':
    import sys
    sys.exit(main())
