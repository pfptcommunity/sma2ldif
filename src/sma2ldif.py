#!/usr/bin/env python3
"""
Convert Sendmail alias files to Proofpoint LDIF format.

This script parses a Sendmail-style alias file using a port of Sendmail's
`readaliases` and `parseaddr` functions, validates aliases, and generates LDIF
entries for Proofpoint. It supports domain mapping, group assignments, and proxy
address expansion, with configurable logging to a rotating file.
"""

import argparse
import logging
import os
import re
import sys
import uuid
from datetime import datetime, timezone, timedelta
from importlib.metadata import version, PackageNotFoundError
from logging import Logger
from logging.handlers import RotatingFileHandler
from pathlib import Path
from time import localtime
from typing import Dict, List, Optional

# Regular expression for validating email addresses per RFC 5322
EMAIL_ADDRESS_REGEX = r'^(?:[a-z0-9!#$%&\'*+/=?^_`{|}~-]+(?:\.[a-z0-9!#$%&\'*+/=?^_`{|}~-]+)*|"(?:[\x01-\x08\x0b\x0c\x0e-\x1f\x21\x23-\x5b\x5d-\x7f]|\\[\x01-\x09\x0b\x0c\x0e-\x7f])*")@(?:(?:[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\.)+[a-z0-9](?:[a-z0-9-]*[a-z0-9])?|\[(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?|[a-z0-9-]*[a-z0-9]:(?:[\x01-\x08\x0b\x0c\x0e-\x1f\x21-\x5a\x53-\x7f]|\\[\x01-\x09\x0b\x0c\x0e-\x7f])+)\])$'

# Constants for logging configuration
DEFAULT_LOG_LEVEL = "warning"  # Default logging level
DEFAULT_MAX_BYTES = 10 * 1024 * 1024  # Default max log file size (10MB)
DEFAULT_BACKUP_COUNT = 5  # Default number of backup log files
DEFAULT_LOG_FILE = "sma2ldif.log"  # Default log file name

# Regular expressions for validation
VALID_DOMAIN_REGEX = re.compile(
    r"(?!-)[a-z0-9-]{1,63}(?<!-)(\.[a-z]{2,63}){1,2}$", re.IGNORECASE
)  # Validates domain syntax (e.g., example.com, sub.example.co.uk)
EMAIL_REGEX = re.compile(EMAIL_ADDRESS_REGEX, re.IGNORECASE)  # Compiled email regex

# UUID namespace for generating deterministic UIDs in LDIF entries
SMA2LDIF_NAMESPACE = uuid.UUID("c11859e0-d9ce-4f59-826c-a5dc23d1bf1e")

# Constants for alias parsing (from Sendmail)
MAXNAME = 256  # Maximum length of an alias address
MAXATOM = 40  # Maximum number of tokens in an alias


def get_version():
    try:
        return version("sma2ldif")
    except PackageNotFoundError:
        return "0.0.0"


class AliasParser:
    """
    A class to parse Sendmail-style alias files, replicating the behavior of
    Sendmail's `readaliases` function with `parseaddr` validation. Parses the file
    during initialization, storing aliases and statistics.

    Attributes:
        file_path (str): Path to the alias file.
        aliases (Dict[str, str]): Dictionary of parsed alias mappings (LHS -> RHS).
        alias_count (int): Number of aliases parsed.
        total_bytes (int): Total bytes in LHS and RHS of all aliases.
        longest (int): Length of the longest RHS.
    """

    def __init__(self, file_path: str, logger: Optional[logging.Logger] = None, exclude_pattern: str = None,
                 include_pattern: str = None, exclude_target: str = None, include_target: str = None):
        """
        Initialize and parse the alias file.

        Args:
            file_path (str): Path to the alias file (e.g., /etc/aliases).
            logger (Optional[logging.Logger]): Logger for error messages. If None,
                a default logger is created with ERROR level and stderr output.
            exclude_pattern (str): Regular expression pattern to exclude aliases (e.g., "(postmaster|noreply.*)").
            include_pattern (str): Regular expression pattern to exclude aliases (e.g., "(postmaster|noreply.*)").

        Raises:
            FileNotFoundError: If the alias file does not exist.
            PermissionError: If the file cannot be read due to permissions.
            UnicodeDecodeError: If the file cannot be decoded as UTF-8.
            Exception: For other parsing errors.
        """
        self.__file_path = file_path
        self.__aliases: Dict[str, str] = {}
        self.__naliases: int = 0
        self.__total_bytes: int = 0
        self.__longest: int = 0
        self.__line_number: int = 0
        self.__filtered_count: int = 0
        self.__invalid_count: int = 0
        self.__exclude_pattern = None
        self.__include_pattern = None
        self.__exclude_target = None
        self.__include_target = None

        # Set up logger
        if logger is None:
            self.__logger = logging.getLogger('sendmail.aliasparser')
            self.__logger.setLevel(logging.ERROR)
            handler = logging.StreamHandler(sys.stderr)
            handler.setFormatter(logging.Formatter('554 5.3.5 %(message)s'))
            self.__logger.addHandler(handler)
            self.__logger.propagate = False
        else:
            self.__logger = logger

        if exclude_pattern:
            try:
                self.__exclude_pattern = re.compile(exclude_pattern)
            except re.error as e:
                self.__logger.error(f"Invalid exclude pattern '{exclude_pattern}': {str(e)}")
                raise

        if include_pattern:
            try:
                self.__include_pattern = re.compile(include_pattern)
            except re.error as e:
                self.__logger.error(f"Invalid include pattern '{include_pattern}': {str(e)}")
                raise

        if exclude_target:
            self.__exclude_target = exclude_target

        if include_target:
            self.__include_target = include_target

        # Parse the file during initialization
        try:
            with open(self.__file_path, 'r', encoding='utf-8-sig') as af:
                line = ''
                while True:
                    # Read the next line
                    raw_line = af.readline()
                    self.__line_number += 1

                    # Check for EOF
                    if not raw_line:
                        if line:
                            # Process any remaining line (no trailing newline)
                            self.__process_line(line)
                        break

                    # Remove trailing newline
                    raw_line = raw_line.rstrip('\n')
                    line += raw_line

                    # Handle continuation lines
                    while self.__is_continuation_line(line, af):
                        next_line = af.readline()
                        self.__line_number += 1
                        if not next_line:
                            break
                        next_line = next_line.rstrip('\n')
                        # Remove backslash for backslash-continued lines
                        if line.endswith('\\'):
                            line = line[:-1] + next_line
                        else:
                            line += next_line

                    # Process the complete line
                    self.__process_line(line)
                    line = ''
        except FileNotFoundError:
            self.__logger.error(f"Alias file {self.__file_path} not found.")
            raise
        except PermissionError:
            self.__logger.error(f"Permission denied accessing {self.__file_path}.")
            raise
        except UnicodeDecodeError as e:
            self.__logger.error(f"Encoding error in {self.__file_path}: {str(e)}")
            raise
        except Exception as e:
            self.__logger.error(f"Failed to parse {self.__file_path}: {str(e)}")
            raise

    def __is_continuation_line(self, line: str, file_obj) -> bool:
        """
        Check if the current line is continued (backslash or leading whitespace).

        A line is continued if it ends with a backslash or if the next line starts
        with a space or tab, per Sendmail's alias file format.

        Args:
            line (str): Current line.
            file_obj: File object to peek at the next character.

        Returns:
            bool: True if the line is continued, False otherwise.
        """
        if line.endswith('\\'):
            return True

        # Peek at the next character
        pos = file_obj.tell()
        next_char = file_obj.read(1)
        file_obj.seek(pos)

        return next_char in ' \t'

    def __is_valid_lhs(self, lhs: str) -> bool:
        """
        Validate the left-hand side (LHS) of an alias, mimicking Sendmail's parseaddr.

        Ensures the LHS adheres to Sendmail's alias syntax, allowing RFC 5322 local-part
        characters (alphanumeric, '.', '_', '-', '@', '!', '#', etc.), rejecting unquoted
        whitespace or control characters, and checking for balanced quotes, parentheses,
        and angle brackets. Enforces maximum length (MAXNAME) and token count (MAXATOM).

        Args:
            lhs (str): The left-hand side (alias name) to validate.

        Returns:
            bool: True if valid, False if invalid (e.g., whitespace, unbalanced quotes).
        """
        if not lhs or len(lhs) > MAXNAME - 1:
            return False

        # Check for whitespace, control characters, and balanced delimiters
        quote_count = 0
        paren_count = 0
        angle_count = 0
        bslash = False
        tokens = 0
        token_length = 0
        i = 0

        while i < len(lhs):
            c = lhs[i]

            # Handle backslash escaping
            if bslash:
                bslash = False
                token_length += 1
                i += 1
                continue

            if c == '\\':
                bslash = True
                i += 1
                continue

            # Handle quotes
            if c == '"':
                quote_count += 1
                i += 1
                continue

            # Handle parentheses (comments)
            if c == '(' and quote_count % 2 == 0:
                paren_count += 1
            elif c == ')' and quote_count % 2 == 0:
                paren_count -= 1
            # Handle angle brackets
            elif c == '<' and quote_count % 2 == 0:
                angle_count += 1
            elif c == '>' and quote_count % 2 == 0:
                angle_count -= 1
            # Check for whitespace or control characters outside quotes
            elif (quote_count % 2 == 0 and
                  (c.isspace() or ord(c) < 32 or ord(c) == 127)):
                return False
            # Count tokens (simplified: split on operators)
            elif c in '()<>,' and quote_count % 2 == 0:
                if token_length > 0:
                    tokens += 1
                    if tokens >= MAXATOM:
                        return False
                    if token_length > MAXNAME:
                        return False
                    token_length = 0
            else:
                token_length += 1

            if token_length > MAXNAME:
                return False

            i += 1

        # Check for balanced delimiters
        if quote_count % 2 != 0 or paren_count != 0 or angle_count != 0:
            return False

        # Final token
        if token_length > 0:
            tokens += 1
            if tokens >= MAXATOM:
                return False

        return True

    def __process_line(self, line: str) -> None:
        """
        Process a single line (or continued line) from the alias file.

        Parses a line into left-hand side (LHS) and right-hand side (RHS), validates
        the LHS, ensures the RHS is non-empty, and stores the alias mapping. Updates
        statistics (alias count, total bytes, longest RHS).

        Args:
            line (str): The line to process.

        Updates:
            self.__aliases, self.__naliases, self.__total_bytes, self.__longest
        """
        # Skip empty lines or comments
        if not line or line.startswith('#'):
            return

        # Check for invalid continuation line (starts with space/tab but not a continuation)
        if line[0] in ' \t':
            self.__logger.error(
                f"File {self.__file_path} Line {self.__line_number}: Non-continuation line starts with space")
            return

        # Split on the first colon
        parts = line.split(':', 1)
        if len(parts) < 2:
            self.__logger.error(f"File {self.__file_path} Line {self.__line_number}: Missing colon")
            return

        lhs, rhs = parts
        lhs = lhs.strip()
        rhs = rhs.strip()

        # Check if RHS is empty
        if not rhs:
            self.__logger.warning(
                f"File {self.__file_path} Line {self.__line_number}: Missing value for alias: {lhs[:40]}")
            self.__invalid_count += 1
            return

        # Special case: lowercase 'postmaster'
        if lhs.lower() == 'postmaster':
            lhs = 'postmaster'

        var_map = {
            "rhs": rhs,
            "lhs": lhs
        }

        # Check if LHS matches the exclude pattern
        if self.__exclude_pattern and self.__exclude_pattern.search(lhs):
            try:
                self.__logger.debug(
                    f"File {self.__file_path} Line {self.__line_number}: Excluded alias: {lhs}:{rhs} (matched --exclude pattern: '{self.__exclude_pattern.pattern}')")
                self.__filtered_count += 1
                return
            except Exception as e:
                self.__logger.error(f"Error applying --exclude pattern '{self.__exclude_pattern.pattern}': {str(e)}")

        # Check if LHS matches the include pattern (if provided)
        if self.__include_pattern and not self.__include_pattern.search(lhs):
            try:
                self.__logger.debug(
                    f"File {self.__file_path} Line {self.__line_number}: Skipped non-included alias: {lhs}:{rhs} (did not match --include pattern: '{self.__include_pattern.pattern}')")
                self.__filtered_count += 1
                return
            except Exception as e:
                self.__logger.error(f"Error applying --include pattern '{self.__include_pattern.pattern}': {str(e)}")
        else:
            if self.__include_pattern:
                self.__logger.debug(
                    f"File {self.__file_path} Line {self.__line_number}: Processing included alias: {lhs}:{rhs} (matched --include pattern: '{self.__include_pattern.pattern}')")

        # Check if RHS matches the exclude pattern
        if self.__exclude_target:
            exclude_target = None
            try:
                exclude_target = substitute_variables(self.__exclude_target, var_map)
                exclude_target_pattern = re.compile(exclude_target)
                if exclude_target_pattern.search(rhs):
                    self.__logger.debug(
                        f"File {self.__file_path} Line {self.__line_number}: Excluded alias: {lhs}:{rhs} (matched --exclude-target pattern: '{exclude_target}')")
                    self.__filtered_count += 1
                    return
            except re.error as e:
                self.__logger.error(f"Invalid --exclude-target pattern '{exclude_target}': {str(e)}")

        # Check if RHS matches the include pattern (if provided)
        if self.__include_target:
            include_target = None
            try:
                include_target = substitute_variables(self.__include_target, var_map)
                include_target_pattern = re.compile(include_target)
                if not include_target_pattern.search(rhs):
                    self.__logger.debug(
                        f"File {self.__file_path} Line {self.__line_number}: Skipped non-included alias: {lhs}:{rhs} (did not match --include-target pattern: '{include_target}')")
                    self.__filtered_count += 1
                    return
                else:
                    self.__logger.debug(
                        f"File {self.__file_path} Line {self.__line_number}: Processing included alias: {lhs}:{rhs} (matched --include-target pattern: '{include_target}')")
            except re.error as e:
                self.__logger.error(f"Invalid --include-target pattern '{include_target}': {str(e)}")

        # Validate LHS (mimicking parseaddr)
        if not self.__is_valid_lhs(lhs):
            self.__logger.warning(f"File {self.__file_path} Line {self.__line_number}: Illegal alias name: {lhs[:40]}")
            self.__invalid_count += 1
            return

        # Store the alias
        self.__aliases[lhs] = rhs
        self.__naliases += 1

        # Update statistics
        lhs_size = len(lhs)
        rhs_size = len(rhs)
        self.__total_bytes += lhs_size + rhs_size
        if rhs_size > self.__longest:
            self.__longest = rhs_size

    @property
    def file_path(self) -> str:
        """Path to the alias file."""
        return self.__file_path

    @property
    def aliases(self) -> Dict[str, str]:
        """Dictionary of parsed alias mappings (LHS -> RHS). Returns a copy to prevent modification."""
        return self.__aliases.copy()

    @property
    def alias_count(self) -> int:
        """Number of aliases parsed."""
        return self.__naliases

    @property
    def total_bytes(self) -> int:
        """Total bytes in LHS and RHS of all aliases."""
        return self.__total_bytes

    @property
    def longest(self) -> int:
        """Length of the longest RHS."""
        return self.__longest

    @property
    def filtered_count(self) -> int:
        """Length of the longest RHS."""
        return self.__filtered_count

    @property
    def invalid_count(self) -> int:
        """Length of the longest RHS."""
        return self.__invalid_count


def log_level_type(level: str) -> str:
    """
    Custom argument type to validate and normalize log levels.

    Ensures the log level is one of 'debug', 'info', 'warning', 'error', or 'critical',
    case-insensitively.

    Args:
        level (str): The log level string to validate.

    Returns:
        str: The normalized (lowercase) log level.

    Raises:
        argparse.ArgumentTypeError: If the log level is invalid.
    """
    level = level.lower()  # Normalize to lowercase
    valid_levels = ['debug', 'info', 'warning', 'error', 'critical']
    if level not in valid_levels:
        raise argparse.ArgumentTypeError(
            f"Invalid log level: {level}. Must be one of {valid_levels}"
        )
    return level


def is_valid_domain_syntax(domain_name: str) -> str:
    """
    Validate domain name syntax using a regular expression.

    Ensures the domain follows standard syntax (e.g., 'example.com', 'sub.example.co.uk'),
    rejecting invalid formats (e.g., '-example.com', 'example.').

    Args:
        domain_name (str): The domain name to validate.

    Returns:
        str: The validated domain name.

    Raises:
        argparse.ArgumentTypeError: If the domain syntax is invalid.
    """
    if not VALID_DOMAIN_REGEX.match(domain_name):
        raise argparse.ArgumentTypeError(f"Invalid domain name syntax: {domain_name}")
    return domain_name


def validate_file_path(path: str, check_readable: bool = False, check_writable: bool = False) -> Path:
    """
    Validate and resolve a file path.

    Checks if the path is readable (for input files) or writable (for output/log files),
    ensuring the parent directory exists and is accessible.

    Args:
        path (str): The file path to validate.
        check_readable (bool): If True, ensure the file exists and is readable.
        check_writable (bool): If True, ensure the parent directory is writable.

    Returns:
        Path: The resolved pathlib.Path object.

    Raises:
        argparse.ArgumentTypeError: If the path is invalid or inaccessible.
    """
    resolved_path = Path(path).resolve()
    if check_readable and not resolved_path.is_file():
        raise argparse.ArgumentTypeError(f"File not found or not readable: {path}")
    if check_writable:
        parent_dir = resolved_path.parent
        if not parent_dir.exists():
            raise argparse.ArgumentTypeError(f"Parent directory does not exist: {parent_dir}")
        if not parent_dir.is_dir() or not os.access(parent_dir, os.W_OK):
            raise argparse.ArgumentTypeError(f"Parent directory is not writable: {parent_dir}")
    return resolved_path


class UTCISOFormatter(logging.Formatter):
    """
    Custom logging formatter for UTC ISO 8601 timestamps.

    Formats log timestamps in ISO 8601 format with UTC timezone and millisecond precision.
    """

    def formatTime(self, record, datefmt=None):
        """
        Format the log record's timestamp as UTC ISO 8601 with milliseconds.

        Args:
            record: The log record containing the timestamp.
            datefmt: Unused, included for compatibility.

        Returns:
            str: The formatted timestamp (e.g., '2023-10-01T12:00:00.123Z').
        """
        utc_time = datetime.fromtimestamp(record.created, tz=timezone.utc)
        return utc_time.isoformat(timespec='milliseconds')


class LocalISOFormatter(logging.Formatter):
    """
    Custom logging formatter for local time ISO 8601 timestamps with timezone offset.

    Formats log timestamps in ISO 8601 format with the local timezone offset and
    millisecond precision.
    """

    def formatTime(self, record, datefmt=None):
        """
        Format the log record's timestamp as local time ISO 8601 with offset.

        Args:
            record: The log record containing the timestamp.
            datefmt: Unused, included for compatibility.

        Returns:
            str: The formatted timestamp (e.g., '2023-10-01T12:00:00.123-04:00').
        """
        # Convert the log record's timestamp to a datetime object
        dt = datetime.fromtimestamp(record.created)
        # Get the local timezone offset from time.localtime()
        local_time = localtime(record.created)
        offset_secs = local_time.tm_gmtoff
        offset = timedelta(seconds=offset_secs)
        tz = timezone(offset)
        # Make the datetime timezone-aware
        dt = dt.replace(tzinfo=tz)
        return dt.isoformat(timespec='milliseconds')


def setup_logging(log_level: str, log_file: str, max_bytes: int, backup_count: int) -> Logger:
    """
    Set up logging with a rotating file handler, without console output, using local time with offset.

    Configures the 'sma2ldif' logger with a rotating file handler, setting the specified log level
    and log file parameters. Uses ISO 8601 timestamps with local timezone offset.

    Args:
        log_level: Logging level ('debug', 'info', 'warning', 'error', 'critical').
        log_file: Path to the log file.
        max_bytes: Maximum size of each log file before rotation (in bytes).
        backup_count: Number of backup log files to keep.

    Raises:
        ValueError: If log_level is invalid or log_file path is invalid.
        OSError: If the log file handler cannot be created.
    """
    # Validate log file path
    log_file_path = validate_file_path(log_file, check_writable=True)

    # Convert string log level to logging level constant
    numeric_level = getattr(logging, log_level.upper(), None)
    if not isinstance(numeric_level, int):
        raise ValueError(f"Invalid log level: {log_level}")

    # Set up the named logger
    logger = logging.getLogger('sma2ldif')
    logger.handlers.clear()
    logger.setLevel(numeric_level)

    # Create rotating file handler
    try:
        file_handler = RotatingFileHandler(
            log_file_path,
            maxBytes=max_bytes,
            backupCount=backup_count,
            encoding='utf-8'
        )
    except OSError as e:
        raise ValueError(f"Failed to create log file handler for {log_file_path}: {str(e)}")

    file_handler.setLevel(numeric_level)

    # Define log format with local time ISO 8601 timestamps including offset
    formatter = LocalISOFormatter('%(asctime)s %(levelname)s %(name)s %(message)s')
    file_handler.setFormatter(formatter)

    # Add only the file handler to the logger
    logger.addHandler(file_handler)

    return logger


def substitute_variables(pattern: str, vars_dict: dict[str, str]):
    """
    Safely substitute variables in a pattern like '^${rhs}@myregexpattern$'.
    Escapes variable values to prevent regex injection.
    """

    def replace_match(match):
        var_name = match.group(1)  # Extract variable name from ${var}
        if var_name not in vars_dict:
            raise ValueError(f"Undefined variable: {var_name}")
        # Escape the variable value to make it safe for regex
        return re.escape(vars_dict[var_name])

    # Match ${variable} placeholders
    substituted = re.sub(r'\${(\w+)}', replace_match, pattern)
    return substituted


def create_ldif_entry(alias: str, domain: str, groups: List[str], proxy_domains: Optional[List[str]] = None) -> str:
    """
    Create a single LDIF entry for Proofpoint.

    Generates an LDIF entry with a distinguished name (dn), UUID-based uid, and
    Proofpoint-specific fields (description, givenName, sn, profileType, mail).
    Optionally includes proxyAddresses for additional domains and memberOf groups.

    Args:
        alias (str): The alias name (LHS or local part of the email address).
        domain (str): The primary domain for the email address.
        groups (List[str]): List of memberOf groups for the entry.
        proxy_domains (Optional[List[str]]): Additional domains for proxyAddresses.

    Returns:
        str: LDIF entry string with fields required by Proofpoint.

    Notes:
        - The uid is generated using UUID5 based on the alias@domain for uniqueness.
        - Hardcoded fields:
          - description: "Auto generated by sma2ldif" (metadata for Proofpoint).
          - profileType: "1" (Proofpoint-specific profile identifier).
          - sn: "sma2ldif" (surname field, set to tool name for consistency).
    """
    alias_email = f"{alias}@{domain}"
    uid = uuid.uuid5(SMA2LDIF_NAMESPACE, alias_email)
    entry = [
        f"dn: {alias_email}",
        f"uid: {uid}",
        "description: Auto generated by sma2ldif",
        f"givenName: {alias}",
        "sn: sma2ldif",
        "profileType: 1",
        f"mail: {alias_email}",
    ]
    if proxy_domains:
        for pa in proxy_domains:
            entry.append(f"proxyAddresses: {alias}@{pa}")
    for group in groups:
        entry.append(f"memberOf: {group}")
    entry.append("")
    return "\n".join(entry)


def generate_pps_ldif(aliases: Dict[str, str], domains: List[str], groups: List[str], expand_proxy: bool) -> str:
    """
    Generate LDIF content for Proofpoint from parsed aliases.

    Creates LDIF entries for each alias, either expanding aliases across multiple
    domains (expand_proxy=True) or using the first domain as primary with others
    as proxyAddresses (expand_proxy=False). Email-like aliases (e.g., user@domain)
    retain their original domain.

    Args:
        aliases (Dict[str, str]): Dictionary of alias mappings (LHS -> RHS).
        domains (List[str]): List of domains, with the first as primary if not expanding.
        groups (List[str]): List of memberOf groups for each LDIF entry.
        expand_proxy (bool): If True, create separate entries for each domain;
                            if False, use proxyAddresses for additional domains.

    Returns:
        str: LDIF content as a newline-separated string of entries.

    Notes:
        - Sorts aliases for consistent output.
        - Email-like aliases are validated with EMAIL_REGEX (RFC 5322).
        - When expand_proxy=False, modifies the domains list by popping the first element.
    """
    ldif_entries = []
    if expand_proxy:
        for alias in sorted(aliases.keys()):
            if EMAIL_REGEX.match(alias):
                parts = alias.split('@')
                ldif_entries.append(create_ldif_entry(parts[0], parts[1], groups))
            else:
                for domain in domains:
                    ldif_entries.append(create_ldif_entry(alias, domain, groups))
    else:
        domain = domains.pop(0)
        for alias in sorted(aliases.keys()):
            if EMAIL_REGEX.match(alias):
                parts = alias.split('@')
                ldif_entries.append(create_ldif_entry(parts[0], parts[1], groups))
            else:
                ldif_entries.append(create_ldif_entry(alias, domain, groups, domains))
    return "\n".join(ldif_entries)


def write_ldif_file(ldif_content: str, output_file: Path, logger: Logger) -> None:
    """
    Write LDIF content to a file.

    Args:
        ldif_content (str): LDIF content to write.
        output_file (Path): Path to the output file.
        logger (Logger): Logger instance.

    Raises:
        PermissionError: If the file cannot be written due to permissions.
        OSError: For other file writing errors.
    """
    try:
        with open(output_file, 'w', encoding='utf-8') as f:
            f.write(ldif_content)
        logger.info(f"LDIF file written to {output_file}")
    except PermissionError:
        logger.error(f"Permission denied writing to {output_file}")
    except Exception as e:
        logger.error(f"Failed to write {output_file}: {str(e)}")


def main() -> None:
    """
    Main function to convert Sendmail alias files to Proofpoint LDIF format.

    Parses command-line arguments, sets up logging, processes the alias file,
    generates LDIF content, and writes it to the output file. Logs configuration,
    alias details, and statistics, exiting with status 1 on errors.

    Exits:
        0: Successful execution.
        1: Error (no aliases, no LDIF content, file errors).
    """
    parser = argparse.ArgumentParser(
        prog="sma2ldif",
        description="Convert Sendmail alias files to Proofpoint LDIF format.",
        formatter_class=lambda prog: argparse.HelpFormatter(prog, max_help_position=80),
        add_help=False
    )

    # Required arguments group
    required = parser.add_argument_group('Required Arguments')
    required.add_argument(
        '--alias-file',
        metavar='<aliases>',
        dest="input_file",
        type=lambda x: validate_file_path(x, check_readable=True),
        required=True,
        help='Path to the input Sendmail aliases file.')
    required.add_argument(
        '--ldif-file', metavar='<ldif>',
        dest="output_file",
        type=lambda x: validate_file_path(x, check_writable=True),
        required=True,
        help='Path to the output LDIF file.')
    required.add_argument(
        '-d', '--domains',
        metavar='<domain>',
        dest="domains",
        required=True,
        nargs='+',
        type=is_valid_domain_syntax,
        help='List of domains for alias processing (first domain is primary).'
    )

    # Processing Options
    processing = parser.add_argument_group('Processing Arguments (Optional)')
    processing.add_argument(
        '-g', '--groups',
        metavar='<group>',
        dest="groups",
        default=[],
        nargs='+',
        help='List of memberOf groups for LDIF entries (default: none).'
    )
    processing.add_argument(
        '-e', '--expand-proxy',
        dest="expand_proxy",
        action='store_true',
        help='Expand proxyAddresses into unique DN entries.')
    processing.add_argument(
        '--exclude',
        metavar='PATTERN',
        dest='exclude_pattern',
        default=None,
        help='Regular expression pattern to exclude aliases. Use \'=\' before patterns starting with a hyphen. (e.g. --exclude="-(approval|outgoing|request)$")'
    )
    processing.add_argument(
        '--include',
        metavar='PATTERN',
        dest='include_pattern',
        default=None,
        help='Regular expression pattern to include aliases. Use \'=\' before patterns starting with a hyphen. (e.g. --include="-(approval|outgoing|request)$")'
    )
    processing.add_argument(
        '--exclude-target',
        metavar='PATTERN',
        dest='exclude_target',
        default=None,
        help='Regular expression pattern to exclude aliases by alias target. The variable ${lhs} can be used as a reference to the alias name. Use \'=\' before patterns starting with a hyphen. (e.g. --exclude-target="${lhs}@domain"'
    )
    processing.add_argument(
        '--include-target',
        metavar='PATTERN',
        dest='include_target',
        default=None,
        help='Regular expression pattern to include aliases by alias target. The variable ${lhs} can be used as a reference to the alias name. Use \'=\' before patterns starting with a hyphen. (e.g. --include-target="${lhs}@domain"'
    )

    # Logging Options
    logging = parser.add_argument_group('Logging Arguments (Optional)')

    logging.add_argument(
        '--log-level',
        default=DEFAULT_LOG_LEVEL,
        type=log_level_type,
        choices=['debug', 'info', 'warning', 'error', 'critical'],
        help=f'Set the logging level (default: {DEFAULT_LOG_LEVEL}).'
    )
    logging.add_argument(
        '-l', '--log-file',
        default=DEFAULT_LOG_FILE,
        type=lambda x: validate_file_path(x, check_writable=True),
        help=f'Set the log file location (default: {DEFAULT_LOG_FILE}).'
    )
    logging.add_argument(
        '-s', '--log-max-size',
        type=int,
        default=DEFAULT_MAX_BYTES,
        help=f'Maximum size of log file in bytes before rotation (default: {DEFAULT_MAX_BYTES}).'
    )
    logging.add_argument(
        '-c', '--log-backup-count',
        type=int,
        default=DEFAULT_BACKUP_COUNT,
        help=f'Number of backup log files to keep (default: {DEFAULT_BACKUP_COUNT}).'
    )

    # Logging Options
    misc = parser.add_argument_group('Help / Version Arguments')

    misc.add_argument('--version', action='version', help="Show the program's version and exit",
                      version=f'sma2ldif {get_version()}')
    misc.add_argument(
        '-h', '--help',
        action='help',
        help='Show this help message and exit.'
    )

    if len(sys.argv) == 1:
        parser.print_usage(sys.stderr)
        sys.exit(1)

    args = parser.parse_args()

    logger = setup_logging(
        args.log_level,
        args.log_file,
        args.log_max_size,
        args.log_backup_count
    )

    logger.info(f"Logging Level: {args.log_level}")
    logger.info(f"Max Log Size: {args.log_max_size}")
    logger.info(f"Log Backup Count: {args.log_backup_count}")
    logger.info(f"Input File: {args.input_file}")
    logger.info(f"Output File: {args.output_file}")
    logger.info(f"Alias Domains: {args.domains}")
    logger.info(f"MemberOf Groups: {args.groups}")

    alias_parser = AliasParser(args.input_file, logger, args.exclude_pattern, args.include_pattern, args.exclude_target,
                               args.include_target)

    logger.info(f"Total Valid Aliases: {alias_parser.alias_count}")
    logger.info(f"Total Filtered Aliases: {alias_parser.filtered_count}")
    logger.info(f"Total Invalid Aliases: {alias_parser.invalid_count}")
    logger.info(f"Longest Alias: {alias_parser.longest}")
    logger.info(f"Total Bytes: {alias_parser.total_bytes}")

    aliases = alias_parser.aliases
    if not aliases:
        logger.error("No aliases to process.")
        sys.exit(1)

    for alias, targets in sorted(aliases.items()):
        logger.debug(f"{alias}: {targets}")

    ldif_content = generate_pps_ldif(aliases, args.domains, args.groups, args.expand_proxy)
    if ldif_content:
        try:
            write_ldif_file(ldif_content, args.output_file, logger)
        except RuntimeError as e:
            logger.error(str(e))
            sys.exit(1)
    else:
        logger.warning("No LDIF content generated.")
        sys.exit(1)


if __name__ == "__main__":
    main()
