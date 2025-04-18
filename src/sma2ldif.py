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
from typing import Dict, List, Set, Optional

EMAIL_ADDRESS_REGEX = r'^(?:[a-z0-9!#$%&\'*+/=?^_`{|}~-]+(?:\.[a-z0-9!#$%&\'*+/=?^_`{|}~-]+)*|"(?:[\x01-\x08\x0b\x0c\x0e-\x1f\x21\x23-\x5b\x5d-\x7f]|\\[\x01-\x09\x0b\x0c\x0e-\x7f])*")@(?:(?:[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\.)+[a-z0-9](?:[a-z0-9-]*[a-z0-9])?|\[(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?|[a-z0-9-]*[a-z0-9]:(?:[\x01-\x08\x0b\x0c\x0e-\x1f\x21-\x5a\x53-\x7f]|\\[\x01-\x09\x0b\x0c\x0e-\x7f])+)\])$'

# Constants
DEFAULT_LOG_LEVEL = "warning"
DEFAULT_MAX_BYTES = 10 * 1024 * 1024
DEFAULT_BACKUP_COUNT = 5
DEFAULT_LOG_FILE = "sma2ldif.log"
VALID_DOMAIN_REGEX = re.compile(r"(?!-)[a-z0-9-]{1,63}(?<!-)(\.[a-z]{2,63}){1,2}$", re.IGNORECASE)
ALIAS_LINE_REGEX = re.compile(r'^([^:]+):\s*(.*)$')
EMAIL_REGEX = re.compile(EMAIL_ADDRESS_REGEX, re.IGNORECASE)
LOCAL_USER_REGEX = re.compile(r'^[\w\-]+$', re.IGNORECASE)
SMA2LDIF_NAMESPACE = uuid.UUID("c11859e0-d9ce-4f59-826c-a5dc23d1bf1e")


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


def classify_target(target: str, aliases: Dict[str, List[str]]) -> str:
    """Classify the type of target.

    Args:
        target: The target string to classify.
        aliases: Dictionary of known aliases.

    Returns:
        String indicating target type (command, file, include, email, alias, local_user, invalid).
    """
    target = target.strip()
    if target.startswith('"|') and target.endswith('"'):
        return 'command'
    if target.startswith('|'):
        return 'command'
    if target.startswith('/'):
        return 'file'
    if target.startswith(':include:'):
        return 'include'
    if '@' in target and EMAIL_REGEX.match(target):
        return 'email'
    if target in aliases:
        return 'alias'
    if LOCAL_USER_REGEX.match(target):
        return 'local_user'
    return 'invalid'


def parse_aliases(file_path: Path) -> Dict[str, List[str]]:
    """Parse a sendmail alias file into a dictionary.

    Args:
        file_path: Path to the alias file.

    Returns:
        Dictionary mapping aliases to their target lists.
    """
    aliases: Dict[str, List[str]] = {}
    current_alias: Optional[str] = None
    current_target: List[str] = []
    seen_aliases: Set[str] = set()

    def split_targets(target_str: str) -> List[str]:
        """Split targets by commas, preserving quoted strings."""
        targets = []
        current = ''
        in_quotes = False
        i = 0
        while i < len(target_str):
            char = target_str[i]
            if char == '"' and (i == 0 or target_str[i - 1] != '\\'):
                in_quotes = not in_quotes
                current += char
            elif char == ',' and not in_quotes:
                if current.strip():
                    targets.append(current.strip())
                current = ''
            else:
                current += char
            i += 1
        if current.strip():
            targets.append(current.strip())
        return targets

    try:
        with open(file_path, 'r', encoding="utf-8-sig") as f:
            for line in f:
                line = line.rstrip()
                if not line or line.startswith('#'):
                    continue

                if line.startswith((' ', '\t')):
                    if current_alias:
                        current_target.append(line.lstrip())
                    else:
                        logging.warning(f"Continuation line ignored without alias: {line}")
                    continue

                match = ALIAS_LINE_REGEX.match(line)
                if match:
                    if current_alias:
                        target_str = ' '.join(current_target)
                        targets = split_targets(target_str)
                        if current_alias in seen_aliases:
                            logging.warning(
                                f"Duplicate alias '{current_alias}' detected. Overwriting previous definition.")
                        aliases[current_alias] = targets
                        seen_aliases.add(current_alias)
                        current_target = []
                    current_alias = match.group(1)
                    if current_alias != current_alias.lower():
                        logging.warning(f"Uppercase alias '{current_alias}' may cause issues with nested aliasing.")
                    if match.group(2):
                        current_target.append(match.group(2))
                else:
                    logging.warning(f"Invalid line skipped: {line}")

            if current_alias:
                target_str = ' '.join(current_target)
                targets = split_targets(target_str)
                if current_alias in seen_aliases:
                    logging.warning(f"Duplicate alias '{current_alias}' detected. Overwriting previous definition.")
                aliases[current_alias] = targets
                seen_aliases.add(current_alias)

    except FileNotFoundError:
        logging.error(f"Alias file {file_path} not found.")
        return {}
    except PermissionError:
        logging.error(f"Permission denied accessing {file_path}.")
        return {}
    except UnicodeDecodeError as e:
        logging.error(f"Encoding error in {file_path}: {str(e)}")
        return {}
    except Exception as e:
        logging.error(f"Failed to parse {file_path}: {str(e)}")
        return {}

    return aliases


def resolve_targets(targets: List[str], aliases: Dict[str, List[str]], domain: str,
                    visited: Optional[Set[str]] = None, max_depth: int = 100) -> List[str]:
    """Recursively resolve targets to emails or local users.

    Args:
        targets: List of targets to resolve.
        aliases: Dictionary of aliases.
        domain: Domain to append to local users.
        visited: Set of visited aliases to detect circular references.
        max_depth: Maximum recursion depth to prevent stack overflow.

    Returns:
        List of resolved email addresses.
    """
    if visited is None:
        visited = set()

    if max_depth <= 0:
        logging.error("Maximum recursion depth exceeded in alias resolution")
        return []

    resolved = []

    for target in targets:
        target_type = classify_target(target, aliases)

        if target_type == 'email':
            resolved.append(target)
        elif target_type == 'local_user':
            resolved.append(f"{target}@{domain}")
        elif target_type == 'alias':
            if target in visited:
                logging.warning(f"Circular reference detected for alias '{target}'")
                continue
            visited.add(target)
            if target in aliases:
                sub_targets = resolve_targets(aliases[target], aliases, domain, visited.copy(), max_depth - 1)
                resolved.extend(sub_targets)
            else:
                logging.warning(f"Alias '{target}' not found in alias map")
            visited.remove(target)
        elif target_type == 'include':
            file_path = target[len(':include:'):]
            try:
                file_path = validate_file_path(file_path, check_readable=True)
                with open(file_path, 'r', encoding="utf-8-sig") as f:
                    file_targets = [line.strip() for line in f if line.strip() and not line.startswith('#')]
                sub_targets = resolve_targets(file_targets, aliases, domain, visited.copy(), max_depth - 1)
                resolved.extend(sub_targets)
            except FileNotFoundError:
                logging.warning(f"Include file '{file_path}' not found")
            except PermissionError:
                logging.warning(f"Permission denied accessing include file '{file_path}'")
            except UnicodeDecodeError as e:
                logging.warning(f"Encoding error in include file '{file_path}': {str(e)}")
            except Exception as e:
                logging.warning(f"Failed to read include file '{file_path}': {str(e)}")
        else:
            logging.warning(f"Skipping non-email target '{target}' ({target_type})")

    # Remove duplicates while preserving order
    seen = set()
    return [t for t in resolved if not (t in seen or seen.add(t))]


def generate_pps_ldif(aliases: Dict[str, List[str]], domains: List[str], groups: List[str]) -> str:
    """Generate Proofpoint LDIF content from parsed and resolved aliases.

    Args:
        aliases: Dictionary of aliases.
        domains: List of domains.
        group: Group name for LDIF entries.

    Returns:
        LDIF content as a string.
    """
    ldif_entries = []
    domain = domains.pop(0)

    for alias in sorted(aliases.keys()):
        alias_email = f"{alias}@{domain}"
        uid = uuid.uuid5(SMA2LDIF_NAMESPACE, alias)

        entry = [
            f"dn: {alias_email}",
            f"uid: {uid}",
            "description: Auto generated by sma2ldif",
            f"givenName: {alias}",
            "sn: sma2ldif",
            "profileType: 1",
            f"mail: {alias_email}",
        ]

        for pa in domains:
            entry.append(f"proxyAddresses: {alias}@{pa}")

        for group in groups:
            entry.append(f"memberOf: {group}")

        entry.append("")

        ldif_entries.append("\n".join(entry))

    return "\n".join(ldif_entries)


def write_ldif_file(ldif_content: str, output_file: Path) -> None:
    """Write LDIF content to a file.

    Args:
        ldif_content: LDIF content to write.
        output_file: Path to the output file.
        force: If True, overwrite existing file.

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
        formatter_class=lambda prog: argparse.HelpFormatter(prog, max_help_position=80)
    )

    parser.add_argument(
        '-i', '--input',
        metavar='<aliases>',
        dest="input_file",
        type=lambda x: validate_file_path(x, check_readable=True),
        required=True,
        help='Path to the input Sendmail aliases file.'
    )
    parser.add_argument(
        '-o', '--output',
        metavar='<ldif>',
        dest="output_file",
        type=lambda x: validate_file_path(x, check_writable=True),
        required=True,
        help='Path to the output LDIF file.'
    )
    parser.add_argument(
        '-d', '--domains',
        metavar='<domain>',
        dest="domains",
        required=True,
        nargs='+',
        type=is_valid_domain_syntax,
        help='List of domains for alias processing (first domain is primary).'
    )
    parser.add_argument(
        '-g', '--groups',
        metavar='<group>',
        dest="groups",
        required=False,
        default=[],
        nargs='+',
        help='List of memberOf groups for alias processing.'
    )
    parser.add_argument(
        '--log-level',
        default=DEFAULT_LOG_LEVEL,
        type=log_level_type,
        choices=['debug', 'info', 'warning', 'error', 'critical'],
        help=f'Set the logging level (default: {DEFAULT_LOG_LEVEL}).'
    )
    parser.add_argument(
        '-l', '--log-file',
        default=DEFAULT_LOG_FILE,
        type=lambda x: validate_file_path(x, check_writable=True),
        help=f'Set the log file location (default: {DEFAULT_LOG_FILE}).'
    )
    parser.add_argument(
        '-s', '--log-max-size',
        type=int,
        default=DEFAULT_MAX_BYTES,
        help=f'Maximum size of log file in bytes before rotation (default: {DEFAULT_MAX_BYTES}).'
    )
    parser.add_argument(
        '-c', '--log-backup-count',
        type=int,
        default=DEFAULT_BACKUP_COUNT,
        help=f'Number of backup log files to keep (default: {DEFAULT_BACKUP_COUNT}).'
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

    aliases = parse_aliases(args.input_file)
    if not aliases:
        logging.error("No aliases to process.")
        sys.exit(1)

    for alias, targets in sorted(aliases.items()):
        logging.info(f"{alias}: {targets}")

    ldif_content = generate_pps_ldif(aliases, args.domains, args.groups)
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
