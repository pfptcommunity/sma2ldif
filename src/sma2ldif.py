#!/usr/bin/env python3
import argparse
import logging
import os
import re
import sys
import uuid
from datetime import datetime, timezone, timedelta
from logging.handlers import RotatingFileHandler
from pathlib import Path
from time import localtime
from typing import Dict, List, Optional

EMAIL_ADDRESS_REGEX = r'^(?:[a-z0-9!#$%&\'*+/=?^_`{|}~-]+(?:\.[a-z0-9!#$%&\'*+/=?^_`{|}~-]+)*|"(?:[\x01-\x08\x0b\x0c\x0e-\x1f\x21\x23-\x5b\x5d-\x7f]|\\[\x01-\x09\x0b\x0c\x0e-\x7f])*")@(?:(?:[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\.)+[a-z0-9](?:[a-z0-9-]*[a-z0-9])?|\[(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?|[a-z0-9-]*[a-z0-9]:(?:[\x01-\x08\x0b\x0c\x0e-\x1f\x21-\x5a\x53-\x7f]|\\[\x01-\x09\x0b\x0c\x0e-\x7f])+)\])$'
# Constants
DEFAULT_LOG_LEVEL = "warning"
DEFAULT_MAX_BYTES = 10 * 1024 * 1024
DEFAULT_BACKUP_COUNT = 5
DEFAULT_LOG_FILE = "sma2ldif.log"
VALID_DOMAIN_REGEX = re.compile(r"(?!-)[a-z0-9-]{1,63}(?<!-)(\.[a-z]{2,63}){1,2}$", re.IGNORECASE)
EMAIL_REGEX = re.compile(EMAIL_ADDRESS_REGEX, re.IGNORECASE)
SMA2LDIF_NAMESPACE = uuid.UUID("c11859e0-d9ce-4f59-826c-a5dc23d1bf1e")

# Alias parser is a port from the sendmail alias.c file with minor pythonic modifications
MAXNAME = 256  # Maximum length of address
MAXATOM = 40  # Maximum number of tokens


class AliasParser:
    """
    A class to parse Sendmail-style alias files, replicating the behavior of
    Sendmail's readaliases function with parseaddr validation. Parses the file
    during initialization, storing aliases and statistics.

    Attributes:
        file_path (str): Path to the alias file.
        aliases (Dict[str, str]): Dictionary of parsed alias mappings (LHS -> RHS).
        alias_count (int): Number of aliases parsed.
        total_bytes (int): Total bytes in LHS and RHS of all aliases.
        longest (int): Length of the longest RHS.
    """

    def __init__(self, file_path: str, logger: Optional[logging.Logger] = None):
        """
        Initialize and parse the alias file.

        Args:
            file_path (str): Path to the alias file (e.g., /etc/aliases).
            logger (Optional[logging.Logger]): Logger for error messages. If None,
                a default logger is created with ERROR level and stderr output.

        Raises:
            IOError: If the file cannot be opened or read.
        """
        self.__file_path = file_path
        self.__aliases: Dict[str, str] = {}
        self.__naliases: int = 0
        self.__total_bytes: int = 0
        self.__longest: int = 0
        self.__line_number: int = 0

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
            logging.error(f"Alias file {self.__file_path} not found.")
            raise
        except PermissionError:
            logging.error(f"Permission denied accessing {self.__file_path}.")
            raise
        except UnicodeDecodeError as e:
            logging.error(f"Encoding error in {self.__file_path}: {str(e)}")
            raise
        except Exception as e:
            logging.error(f"Failed to parse {self.__file_path}: {str(e)}")
            raise

    def __is_continuation_line(self, line: str, file_obj) -> bool:
        """
        Check if the current line is continued (backslash or leading whitespace).

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
        Validate the LHS of an alias, mimicking Sendmail's parseaddr.

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

        # Validate LHS (mimicking parseaddr)
        if not self.__is_valid_lhs(lhs):
            self.__logger.error(f"File {self.__file_path} Line {self.__line_number}: Illegal alias name: {lhs[:40]}")
            return

        # Check if RHS is empty
        if not rhs:
            self.__logger.error(
                f"File {self.__file_path} Line {self.__line_number}: Missing value for alias: {lhs[:40]}")
            return

        # Special case: lowercase 'postmaster'
        if lhs.lower() == 'postmaster':
            lhs = 'postmaster'

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
        """Dictionary of parsed alias mappings (LHS -> RHS)."""
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


def log_level_type(level: str) -> str:
    """Custom type to make log level case-insensitive."""
    level = level.lower()  # Normalize to uppercase
    valid_levels = ['debug', 'info', 'warning', 'error', 'critical']
    if level not in valid_levels:
        raise argparse.ArgumentTypeError(
            f"Invalid log level: {level}. Must be one of {valid_levels}"
        )
    return level


def is_valid_domain_syntax(domain_name: str) -> str:
    """Validate domain name syntax using regex."""
    if not VALID_DOMAIN_REGEX.match(domain_name):
        raise argparse.ArgumentTypeError(f"Invalid domain name syntax: {domain_name}")
    return domain_name


def validate_file_path(path: str, check_readable: bool = False, check_writable: bool = False) -> Path:
    """Validate and resolve file path."""
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


# Custom formatter for UTC ISO 8601 timestamps
class UTCISOFormatter(logging.Formatter):
    def formatTime(self, record, datefmt=None):
        utc_time = datetime.fromtimestamp(record.created, tz=timezone.utc)
        return utc_time.isoformat(timespec='milliseconds')


# Custom formatter for local time ISO 8601 timestamps with offset
class LocalISOFormatter(logging.Formatter):
    def formatTime(self, record, datefmt=None):
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


def setup_logging(log_level: str, log_file: str, max_bytes: int, backup_count: int) -> None:
    """Set up logging with a rotating file handler, without console output, using local time with offset.

    Args:
        log_level: Logging level (DEBUG, INFO, WARNING, ERROR, CRITICAL).
        log_file: Path to the log file.
        max_bytes: Maximum size of each log file before rotation (in bytes).
        backup_count: Number of backup log files to keep.

    Raises:
        ValueError: If log_level is invalid or log_file path is invalid.
    """
    # Validate log file path
    log_file_path = validate_file_path(log_file, check_writable=True)

    # Convert string log level to logging level constant
    numeric_level = getattr(logging, log_level.upper(), None)
    if not isinstance(numeric_level, int):
        raise ValueError(f"Invalid log level: {log_level}")

    # Clear any existing handlers to prevent duplicate logging
    logging.getLogger('').handlers.clear()

    # Set up the root logger
    logging.getLogger('').setLevel(numeric_level)

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

    # Add only the file handler to the root logger
    logging.getLogger('').addHandler(file_handler)


def create_ldif_entry(alias: str, domain: str, groups: List[str], proxy_domains: Optional[List[str]] = None) -> str:
    """Create a single LDIF entry."""
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
    """Generate LDIF content for Proofpoint."""
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


def write_ldif_file(ldif_content: str, output_file: Path) -> None:
    """Write LDIF content to a file.

    Args:
        ldif_content: LDIF content to write.
        output_file: Path to the output file.

    Raises:
        RuntimeError: If output file exists and force is False.
    """
    try:
        with open(output_file, 'w', encoding='utf-8') as f:
            f.write(ldif_content)
        logging.info(f"LDIF file written to {output_file}")
    except PermissionError:
        logging.error(f"Permission denied writing to {output_file}")
    except Exception as e:
        logging.error(f"Failed to write {output_file}: {str(e)}")


def main() -> None:
    """Main function to convert Sendmail alias files to Proofpoint LDIF format."""
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

    # Optional arguments group
    optional = parser.add_argument_group('Optional Arguments')
    optional.add_argument(
        '-g', '--groups',
        metavar='<group>',
        dest="groups",
        default=[],
        nargs='+',
        help='List of memberOf groups for LDIF entries (default: none).'
    )
    optional.add_argument(
        '-e', '--expand-proxy',
        dest="expand_proxy",
        action='store_true',
        help='Expand proxyAddresses into unique DN entries.')
    optional.add_argument(
        '--log-level',
        default=DEFAULT_LOG_LEVEL,
        type=log_level_type,
        choices=['debug', 'info', 'warning', 'error', 'critical'],
        help=f'Set the logging level (default: {DEFAULT_LOG_LEVEL}).'
    )
    optional.add_argument(
        '-l', '--log-file',
        default=DEFAULT_LOG_FILE,
        type=lambda x: validate_file_path(x, check_writable=True),
        help=f'Set the log file location (default: {DEFAULT_LOG_FILE}).'
    )
    optional.add_argument(
        '-s', '--log-max-size',
        type=int,
        default=DEFAULT_MAX_BYTES,
        help=f'Maximum size of log file in bytes before rotation (default: {DEFAULT_MAX_BYTES}).'
    )
    optional.add_argument(
        '-c', '--log-backup-count',
        type=int,
        default=DEFAULT_BACKUP_COUNT,
        help=f'Number of backup log files to keep (default: {DEFAULT_BACKUP_COUNT}).'
    )
    optional.add_argument(
        '-h', '--help',
        action='help',
        help='Show this help message and exit.'
    )

    if len(sys.argv) == 1:
        parser.print_usage(sys.stderr)
        sys.exit(1)

    args = parser.parse_args()

    setup_logging(
        args.log_level,
        args.log_file,
        args.log_max_size,
        args.log_backup_count
    )

    logging.info(f"Logging Level: {args.log_level}")
    logging.info(f"Max Log Size: {args.log_max_size}")
    logging.info(f"Log Backup Count: {args.log_backup_count}")
    logging.info(f"Input File: {args.input_file}")
    logging.info(f"Output File: {args.output_file}")
    logging.info(f"Alias Domains: {args.domains}")
    logging.info(f"MemberOf Groups: {args.groups}")

    parser = AliasParser(args.input_file, logging.getLogger())

    logging.info(f"Total Aliases: {parser.alias_count}")
    logging.info(f"Longest Alias: {parser.longest}")
    logging.info(f"Total Bytes: {parser.total_bytes}")

    aliases = parser.aliases
    if not aliases:
        logging.error("No aliases to process.")
        sys.exit(1)

    for alias, targets in sorted(aliases.items()):
        logging.info(f"{alias}: {targets}")

    ldif_content = generate_pps_ldif(aliases, args.domains, args.groups, args.expand_proxy)
    if ldif_content:
        try:
            write_ldif_file(ldif_content, args.output_file)
        except RuntimeError as e:
            logging.error(str(e))
            sys.exit(1)
    else:
        logging.warning("No LDIF content generated.")
        sys.exit(1)


if __name__ == "__main__":
    main()
