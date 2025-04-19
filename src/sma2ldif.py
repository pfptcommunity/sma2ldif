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

import paramiko

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
    """Custom type to make log level case-insensitive.

    Args:
        level (str): The log level to validate.

    Returns:
        str: The normalized log level.

    Raises:
        argparse.ArgumentTypeError: If the log level is invalid.
    """
    level = level.lower()
    valid_levels = ['debug', 'info', 'warning', 'error', 'critical']
    if level not in valid_levels:
        raise argparse.ArgumentTypeError(
            f"Invalid log level: {level}. Must be one of {valid_levels}"
        )
    return level


def is_valid_domain_syntax(domain_name: str) -> str:
    """Validate domain name syntax using regex.

    Args:
        domain_name (str): The domain name to validate.

    Returns:
        str: The validated domain name.

    Raises:
        argparse.ArgumentTypeError: If the domain name syntax is invalid.
    """
    if not VALID_DOMAIN_REGEX.match(domain_name):
        raise argparse.ArgumentTypeError(f"Invalid domain name syntax: {domain_name}")
    return domain_name


def validate_file_path(path: str, check_readable: bool = False, check_writable: bool = False) -> Path:
    """Validate and resolve file path.

    Args:
        path (str): The file path to validate.
        check_readable (bool): If True, check if the file exists and is readable.
        check_writable (bool): If True, check if the parent directory is writable.

    Returns:
        Path: The resolved file path.

    Raises:
        argparse.ArgumentTypeError: If the path is invalid or permissions are insufficient.
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
    """Custom formatter for UTC ISO 8601 timestamps."""

    def formatTime(self, record, datefmt=None):
        utc_time = datetime.fromtimestamp(record.created, tz=timezone.utc)
        return utc_time.isoformat(timespec='milliseconds')


class LocalISOFormatter(logging.Formatter):
    """Custom formatter for local time ISO 8601 timestamps with offset."""

    def formatTime(self, record, datefmt=None):
        dt = datetime.fromtimestamp(record.created)
        local_time = localtime(record.created)
        offset_secs = local_time.tm_gmtoff
        offset = timedelta(seconds=offset_secs)
        tz = timezone(offset)
        dt = dt.replace(tzinfo=tz)
        return dt.isoformat(timespec='milliseconds')


def setup_logging(log_level: str, log_file: str, max_bytes: int, backup_count: int) -> None:
    """Set up logging with a rotating file handler, without console output, using local time with offset.

    Args:
        log_level (str): Logging level (DEBUG, INFO, WARNING, ERROR, CRITICAL).
        log_file (str): Path to the log file.
        max_bytes (int): Maximum size of each log file before rotation (in bytes).
        backup_count (int): Number of backup log files to keep.

    Raises:
        ValueError: If log_level is invalid or log_file path is invalid.
    """
    log_file_path = validate_file_path(log_file, check_writable=True)
    numeric_level = getattr(logging, log_level.upper(), None)
    if not isinstance(numeric_level, int):
        raise ValueError(f"Invalid log level: {log_level}")

    logging.getLogger('').handlers.clear()
    logging.getLogger('').setLevel(numeric_level)

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
    formatter = LocalISOFormatter('%(asctime)s %(levelname)s %(name)s %(message)s')
    file_handler.setFormatter(formatter)
    logging.getLogger('').addHandler(file_handler)


def secure_scp_transfer(
        local_file: str,
        remote_host: str,
        remote_user: str,
        remote_dir: str,
        ssh_key: str,
        ssh_port: int
) -> bool:
    """Perform a secure SCP transfer of a file to a remote host using Paramiko.

    Args:
        local_file (str): Path to the local file to transfer.
        remote_host (str): Remote host address (e.g., IP or domain).
        remote_user (str): Username on the remote host.
        remote_dir (str): Destination directory on the remote host.
        ssh_key (str): Path to the SSH private key file.
        ssh_port (int): SSH port number for the connection.

    Returns:
        bool: True if the transfer succeeds, False otherwise.

    Raises:
        paramiko.AuthenticationException: If authentication fails.
        paramiko.SSHException: If an SSH-related error occurs.
        Exception: For other unexpected errors during transfer.
    """
    try:
        if not os.path.isfile(local_file):
            logging.error(f"Local file {local_file} does not exist")
            return False

        ssh: paramiko.SSHClient = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())

        private_key: paramiko.Ed25519Key = paramiko.Ed25519Key(filename=ssh_key)
        ssh.connect(
            hostname=remote_host,
            username=remote_user,
            port=ssh_port,
            pkey=private_key,
            look_for_keys=False,
            allow_agent=False
        )

        with ssh.open_sftp() as sftp:
            remote_path: str = os.path.join(remote_dir, os.path.basename(local_file))
            sftp.put(local_file, remote_path)
            logging.info(f"Successfully transferred {local_file} to {remote_host}:{remote_path}")

        ssh.close()
        return True

    except paramiko.AuthenticationException:
        logging.error("Authentication failed. Check SSH key and remote user.")
        return False
    except paramiko.SSHException as e:
        logging.error(f"SSH error: {str(e)}")
        return False
    except Exception as e:
        logging.error(f"Error during transfer: {str(e)}")
        return False


def classify_target(target: str, aliases: Dict[str, List[str]]) -> str:
    """Classify the type of target.

    Args:
        target (str): The target string to classify.
        aliases (Dict[str, List[str]]): Dictionary of known aliases.

    Returns:
        str: Target type (command, file, include, email, alias, local_user, invalid).
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
        file_path (Path): Path to the alias file.

    Returns:
        Dict[str, List[str]]: Dictionary mapping aliases to their target lists.
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
        targets (List[str]): List of targets to resolve.
        aliases (Dict[str, List[str]]): Dictionary of aliases.
        domain (str): Domain to append to local users.
        visited (Optional[Set[str]]): Set of visited aliases to detect circular references.
        max_depth (int): Maximum recursion depth to prevent stack overflow.

    Returns:
        List[str]: List of resolved email addresses.
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

    seen = set()
    return [t for t in resolved if not (t in seen or seen.add(t))]


def create_ldif_entry(alias: str, domain: str, groups: List[str], proxy_domains: Optional[List[str]] = None) -> str:
    """Create a single LDIF entry for an alias and domain.

    Args:
        alias (str): The alias for the email address.
        domain (str): The domain for the email address.
        groups (List[str]): List of group names for the 'memberOf' attribute.
        proxy_domains (Optional[List[str]]): Optional list of domains for 'proxyAddresses' attribute.

    Returns:
        str: A string representing the LDIF entry.
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


def generate_pps_ldif(aliases: Dict[str, List[str]], domains: List[str], groups: List[str], expand_proxy: bool) -> str:
    """Generate LDIF content for Proofpoint from aliases, domains, and groups.

    Args:
        aliases (Dict[str, List[str]]): Dictionary mapping aliases to their attributes.
        domains (List[str]): List of domains to use in LDIF entries.
        groups (List[str]): List of group names for the 'memberOf' attribute.
        expand_proxy (bool): If True, create separate entries for each domain; if False, use proxyAddresses.

    Returns:
        str: A string containing the complete LDIF content.
    """
    ldif_entries = []

    if expand_proxy:
        for alias in sorted(aliases.keys()):
            for domain in domains:
                ldif_entries.append(create_ldif_entry(alias, domain, groups))
    else:
        domain = domains.pop(0)
        for alias in sorted(aliases.keys()):
            ldif_entries.append(create_ldif_entry(alias, domain, groups, domains))

    return "\n".join(ldif_entries)


def write_ldif_file(ldif_content: str, output_file: Path) -> None:
    """Write LDIF content to a file.

    Args:
        ldif_content (str): LDIF content to write.
        output_file (Path): Path to the output file.

    Raises:
        PermissionError: If writing to the output file is not permitted.
        Exception: For other unexpected errors during file writing.
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
    """Main function to convert Sendmail alias files to Proofpoint LDIF format and optionally transfer via SCP.

    This function parses command-line arguments, sets up logging, processes the alias file,
    generates LDIF content, writes it to a local file, and optionally transfers the file to a remote host.

    Args:
        None

    Returns:
        None: Exits with status code 1 if processing or transfer fails.

    Raises:
        SystemExit: If required arguments are missing or processing fails.
    """
    parser = argparse.ArgumentParser(
        prog="sma2ldif",
        description="Convert Sendmail alias files to Proofpoint LDIF format.",
        formatter_class=lambda prog: argparse.HelpFormatter(prog, max_help_position=80),
        add_help=False
    )

    # Required arguments group
    required_group = parser.add_argument_group('Required Arguments')
    required_group.add_argument(
        '-i', '--input',
        metavar='<aliases>',
        dest="input_file",
        type=lambda x: validate_file_path(x, check_readable=True),
        required=True,
        help='Path to the input Sendmail aliases file.'
    )
    required_group.add_argument(
        '-o', '--output',
        metavar='<ldif>',
        dest="output_file",
        type=lambda x: validate_file_path(x, check_writable=True),
        required=True,
        help='Path to the output LDIF file.'
    )
    required_group.add_argument(
        '-d', '--domains',
        metavar='<domain>',
        dest="domains",
        required=True,
        nargs='+',
        type=is_valid_domain_syntax,
        help='List of domains for alias processing (first domain is primary).'
    )

    # Optional arguments group
    optional_group = parser.add_argument_group('Optional Arguments')
    optional_group.add_argument(
        '-g', '--groups',
        metavar='<group>',
        dest="groups",
        default=[],
        nargs='+',
        help='List of memberOf groups for LDIF entries (default: none).'
    )
    optional_group.add_argument(
        '-e', '--expand-proxy',
        dest="expand_proxy",
        action='store_true',
        help='Expand proxyAddresses into their own unique DN entries'
    )
    optional_group.add_argument(
        '--log-level',
        default=DEFAULT_LOG_LEVEL,
        type=log_level_type,
        choices=['debug', 'info', 'warning', 'error', 'critical'],
        help=f'Set the logging level (default: {DEFAULT_LOG_LEVEL}).'
    )
    optional_group.add_argument(
        '-l', '--log-file',
        default=DEFAULT_LOG_FILE,
        type=lambda x: validate_file_path(x, check_writable=True),
        help=f'Set the log file location (default: {DEFAULT_LOG_FILE}).'
    )
    optional_group.add_argument(
        '-s', '--log-max-size',
        type=int,
        default=DEFAULT_MAX_BYTES,
        help=f'Maximum size of log file in bytes before rotation (default: {DEFAULT_MAX_BYTES}).'
    )
    optional_group.add_argument(
        '-c', '--log-backup-count',
        type=int,
        default=DEFAULT_BACKUP_COUNT,
        help=f'Number of backup log files to keep (default: {DEFAULT_BACKUP_COUNT}).'
    )
    optional_group.add_argument(
        '--scp',
        action='store_true',
        help='Enable SCP transfer of the LDIF file to a remote host.'
    )
    optional_group.add_argument(
        '--remote-host',
        help='Remote host address for SCP (required if --scp is used).'
    )
    optional_group.add_argument(
        '--remote-user',
        help='Remote username for SCP (required if --scp is used).'
    )
    optional_group.add_argument(
        '--remote-dir',
        help='Remote destination directory for SCP (required if --scp is used).'
    )
    optional_group.add_argument(
        '--ssh-key',
        help='Path to the SSH private key for SCP (required if --scp is used).'
    )
    optional_group.add_argument(
        '--ssh-port',
        type=int,
        default=22,
        help='SSH port for SCP (default: 22).'
    )
    optional_group.add_argument(
        '-h', '--help',
        action='help',
        help='Show this help message and exit.'
    )

    if len(sys.argv) == 1:
        parser.print_usage(sys.stderr)
        sys.exit(1)

    args = parser.parse_args()

    # Validate SCP arguments if --scp is used
    if args.scp:
        required_scp_args = ['remote_host', 'remote_user', 'remote_dir', 'ssh_key']
        missing_args = [arg for arg in required_scp_args if getattr(args, arg) is None]
        if missing_args:
            parser.error(
                f"The following arguments are required when --scp is used: {', '.join('--' + arg.replace('_', '-') for arg in missing_args)}")

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
    logging.info(f"Expand Proxy: {args.expand_proxy}")
    if args.scp:
        logging.info(f"SCP Enabled: True")
        logging.info(f"Remote Host: {args.remote_host}")
        logging.info(f"Remote User: {args.remote_user}")
        logging.info(f"Remote Dir: {args.remote_dir}")
        logging.info(f"SSH Key: {args.ssh_key}")
        logging.info(f"SSH Port: {args.ssh_port}")

    aliases = parse_aliases(args.input_file)
    if not aliases:
        logging.error("No aliases to process.")
        sys.exit(1)

    for alias, targets in sorted(aliases.items()):
        logging.info(f"{alias}: {targets}")

    ldif_content = generate_pps_ldif(aliases, args.domains, args.groups, args.expand_proxy)
    if ldif_content:
        try:
            write_ldif_file(ldif_content, args.output_file)
            if args.scp:
                success = secure_scp_transfer(
                    local_file=str(args.output_file),
                    remote_host=args.remote_host,
                    remote_user=args.remote_user,
                    remote_dir=args.remote_dir,
                    ssh_key=args.ssh_key,
                    ssh_port=args.ssh_port
                )
                if not success:
                    logging.error("SCP transfer failed")
                    sys.exit(1)
        except RuntimeError as e:
            logging.error(str(e))
            sys.exit(1)
    else:
        logging.warning("No LDIF content generated.")
        sys.exit(1)


if __name__ == "__main__":
    main()
