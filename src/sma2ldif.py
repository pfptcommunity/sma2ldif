#!/usr/bin/env python3
import argparse
import logging
import os
import re
import sys
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone, timedelta
from getpass import getpass
from logging.handlers import RotatingFileHandler
from pathlib import Path
from time import localtime
from typing import Dict, List, Set, Optional, Tuple
from tqdm import tqdm

from sftp_client import SFTPClient, SSHKeyManager, KeyValidationError, AuthenticationError, SFTPClientError, \
    TransferError


@dataclass
class Config:
    """Configuration constants and regex patterns."""
    DEFAULT_LOG_LEVEL: str = "warning"
    DEFAULT_MAX_BYTES: int = 10 * 1024 * 1024
    DEFAULT_BACKUP_COUNT: int = 5
    DEFAULT_LOG_FILE: str = "sma2ldif.log"
    SMA2LDIF_NAMESPACE: uuid.UUID = uuid.UUID("c11859e0-d9ce-4f59-826c-a5dc23d1bf1e")
    EMAIL_ADDRESS_REGEX: str = (
        r'^(?:[a-z0-9!#$%&\'*+/=?^_`{|}~-]+(?:\.[a-z0-9!#$%&\'*+/=?^_`{|}~-]+)*|'
        r'"(?:[\x01-\x08\x0b\x0c\x0e-\x1f\x21\x23-\x5b\x5d-\x7f]|\$$ \x01-\x09\x0b\x0c\x0e-\x7f])*")'
        r'@(?:(?:[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\.)+[a-z0-9](?:[a-z0-9-]*[a-z0-9])?|'
        r'\[(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}'
        r'(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?|[a-z0-9-]*[a-z0-9]:'
        r'(?:[\x01-\x08\x0b\x0c\x0e-\x1f\x21-\x5a\x53-\x7f]|\\[\x01-\x09\x0b\x0c\x0e-\x7f])+) $$)$'
    )
    VALID_DOMAIN_REGEX: re.Pattern = re.compile(r"(?!-)[a-z0-9-]{1,63}(?<!-)(\.[a-z]{2,63}){1,2}$", re.IGNORECASE)
    ALIAS_LINE_REGEX: re.Pattern = re.compile(r'^([^:]+):\s*(.*)$')
    EMAIL_REGEX: re.Pattern = re.compile(EMAIL_ADDRESS_REGEX, re.IGNORECASE)
    LOCAL_USER_REGEX: re.Pattern = re.compile(r'^[\w\-]+$', re.IGNORECASE)


@dataclass
class Args:
    """Parsed command-line arguments."""
    input_file: Path
    output_file: Path
    domains: List[str]
    groups: List[str]
    expand_proxy: bool
    log_level: str
    log_file: Path
    log_max_size: int
    log_backup_count: int
    transfer: bool
    remote: Optional[Tuple[str, str, Optional[str]]]
    identity_file: Optional[Path]
    ssh_port: int
    quiet: bool


def log_level_type(level: str) -> str:
    """Validate log level."""
    level = level.lower()
    valid_levels = ['debug', 'info', 'warning', 'error', 'critical']
    if level not in valid_levels:
        raise argparse.ArgumentTypeError(f"Invalid log level: {level}. Must be one of {valid_levels}")
    return level


def is_valid_domain_syntax(domain_name: str) -> str:
    """Validate domain name syntax."""
    if not Config.VALID_DOMAIN_REGEX.match(domain_name):
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


def parse_remote(remote: str) -> Tuple[str, str, Optional[str]]:
    """Parse remote specification (username@hostname[:directory])."""
    if '@' not in remote:
        raise argparse.ArgumentTypeError(
            f"Invalid remote specification: {remote}. Must be username@hostname[:directory]")
    username, rest = remote.split('@', 1)
    if not username:
        raise argparse.ArgumentTypeError(f"Invalid remote specification: {remote}. Username cannot be empty")
    if ':' in rest:
        hostname, directory = rest.split(':', 1)
        if not directory:
            directory = None
    else:
        hostname, directory = rest, None
    if not hostname:
        raise argparse.ArgumentTypeError(f"Invalid remote specification: {remote}. Hostname cannot be empty")
    return username, hostname, directory


def validate_ssh_port(port: int) -> int:
    """Validate SSH port number."""
    if not 1 <= port <= 65535:
        raise argparse.ArgumentTypeError(f"Invalid SSH port: {port}. Must be between 1 and 65535.")
    return port


class UTCISOFormatter(logging.Formatter):
    """Formatter for UTC ISO 8601 timestamps."""

    def formatTime(self, record, datefmt=None):
        utc_time = datetime.fromtimestamp(record.created, tz=timezone.utc)
        return utc_time.isoformat(timespec='milliseconds')


class LocalISOFormatter(logging.Formatter):
    """Formatter for local time ISO 8601 timestamps with offset."""

    def formatTime(self, record, datefmt=None):
        dt = datetime.fromtimestamp(record.created)
        local_time = localtime(record.created)
        offset_secs = local_time.tm_gmtoff
        offset = timedelta(seconds=offset_secs)
        tz = timezone(offset)
        dt = dt.replace(tzinfo=tz)
        return dt.isoformat(timespec='milliseconds')


def setup_logging(args: Args) -> None:
    """Set up logging with rotating file handler and stderr for errors."""
    numeric_level = getattr(logging, args.log_level.upper(), None)
    if not isinstance(numeric_level, int):
        raise ValueError(f"Invalid log level: {args.log_level}")
    logging.getLogger('').handlers.clear()
    logging.getLogger('').setLevel(numeric_level)
    try:
        file_handler = RotatingFileHandler(
            args.log_file,
            maxBytes=args.log_max_size,
            backupCount=args.log_backup_count,
            encoding='utf-8'
        )
    except OSError as e:
        print(f"Error: Failed to create log file handler for {args.log_file}: {str(e)}", file=sys.stderr)
        sys.exit(2)
    file_handler.setLevel(numeric_level)
    file_formatter = LocalISOFormatter('%(asctime)s %(levelname)s %(name)s %(message)s')
    file_handler.setFormatter(file_formatter)
    logging.getLogger('').addHandler(file_handler)
    # Always add stderr handler for ERROR and CRITICAL
    error_handler = logging.StreamHandler(sys.stderr)
    error_handler.setLevel(logging.ERROR)
    error_handler.setFormatter(logging.Formatter('%(levelname)s: %(message)s'))
    error_handler.addFilter(lambda record: record.levelno >= logging.ERROR)
    logging.getLogger('').addHandler(error_handler)
    # Add info handler for non-quiet mode
    if not args.quiet:
        info_handler = logging.StreamHandler(sys.stderr)
        info_handler.setLevel(logging.INFO)
        info_handler.setFormatter(logging.Formatter('%(message)s'))
        info_handler.addFilter(lambda record: record.levelno < logging.ERROR)
        logging.getLogger('').addHandler(info_handler)
    logging.getLogger("paramiko").setLevel(logging.WARNING)


def split_targets(target_str: str) -> List[str]:
    """Split alias targets by commas, preserving quoted strings."""
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


def parse_aliases(file_path: Path) -> Dict[str, List[str]]:
    """Parse a sendmail alias file into a dictionary."""
    aliases: Dict[str, List[str]] = {}
    current_alias: Optional[str] = None
    current_target: List[str] = []
    seen_aliases: Set[str] = set()
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
                match = Config.ALIAS_LINE_REGEX.match(line)
                if match:
                    if current_alias:
                        target_str = ' '.join(current_target)
                        targets = split_targets(target_str)
                        if current_alias in seen_aliases:
                            logging.warning(f"Duplicate alias '{current_alias}' detected. Overwriting.")
                        aliases[current_alias] = targets
                        seen_aliases.add(current_alias)
                        current_target = []
                    current_alias = match.group(1)
                    if current_alias != current_alias.lower():
                        logging.warning(f"Uppercase alias '{current_alias}' may cause issues.")
                    if match.group(2):
                        current_target.append(match.group(2))
                else:
                    logging.warning(f"Invalid line skipped: {line}")
            if current_alias:
                target_str = ' '.join(current_target)
                targets = split_targets(target_str)
                if current_alias in seen_aliases:
                    logging.warning(f"Duplicate alias '{current_alias}' detected. Overwriting.")
                aliases[current_alias] = targets
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


def classify_target(target: str, aliases: Dict[str, List[str]]) -> str:
    """Classify the type of target."""
    target = target.strip()
    if target.startswith('"|') and target.endswith('"') or target.startswith('|'):
        return 'command'
    if target.startswith('/'):
        return 'file'
    if target.startswith(':include:'):
        return 'include'
    if '@' in target and Config.EMAIL_REGEX.match(target):
        return 'email'
    if target in aliases:
        return 'alias'
    if Config.LOCAL_USER_REGEX.match(target):
        return 'local_user'
    return 'invalid'


def resolve_targets(targets: List[str], aliases: Dict[str, List[str]], domain: str,
                    visited: Optional[Set[str]] = None, max_depth: int = 100) -> List[str]:
    """Recursively resolve alias targets to emails or local users."""
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
                logging.warning(f"Alias '{target}' not found")
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
    """Create a single LDIF entry."""
    alias_email = f"{alias}@{domain}"
    uid = uuid.uuid5(Config.SMA2LDIF_NAMESPACE, alias_email)
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
    """Generate LDIF content for Proofpoint."""
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


def write_ldif_file(ldif_content: str, output_file: Path, quiet: bool = False) -> None:
    """Write LDIF content to a file."""
    try:
        with open(output_file, 'w', encoding='utf-8') as f:
            f.write(ldif_content)
        if not quiet:
            logging.info(f"LDIF file written to {output_file}")
    except PermissionError:
        logging.error(f"Permission denied writing to {output_file}")
        sys.exit(1)
    except Exception as e:
        logging.error(f"Failed to write {output_file}: {str(e)}")
        sys.exit(1)


def parse_args() -> Args:
    """Parse and validate command-line arguments."""
    parser = argparse.ArgumentParser(
        prog="sma2ldif",
        description="Convert Sendmail alias files to Proofpoint LDIF format.",
        formatter_class=lambda prog: argparse.HelpFormatter(prog, max_help_position=80),
        add_help=False
    )
    required = parser.add_argument_group('Required Arguments')
    required.add_argument('--alias-file', metavar='<aliases>', dest="input_file",
                          type=lambda x: validate_file_path(x, check_readable=True), required=True,
                          help='Path to the input Sendmail aliases file.')
    required.add_argument('--ldif-file', metavar='<ldif>', dest="output_file",
                          type=lambda x: validate_file_path(x, check_writable=True), required=True,
                          help='Path to the output LDIF file.')
    required.add_argument('-d', '--domains', metavar='<domain>', dest="domains", required=True, nargs='+',
                          type=is_valid_domain_syntax, help='List of domains (first is primary).')
    optional = parser.add_argument_group('Optional Arguments')
    optional.add_argument('-g', '--groups', metavar='<group>', dest="groups", default=[], nargs='+',
                          help='List of memberOf groups (default: none).')
    optional.add_argument('-e', '--expand-proxy', dest="expand_proxy", action='store_true',
                          help='Expand proxyAddresses into unique DN entries.')
    optional.add_argument('--log-level', default=Config.DEFAULT_LOG_LEVEL, type=log_level_type,
                          choices=['debug', 'info', 'warning', 'error', 'critical'],
                          help=f'Logging level (default: {Config.DEFAULT_LOG_LEVEL}).')
    optional.add_argument('-l', '--log-file', default=Config.DEFAULT_LOG_FILE,
                          type=lambda x: validate_file_path(x, check_writable=True),
                          help=f'Log file location (default: {Config.DEFAULT_LOG_FILE}).')
    optional.add_argument('-s', '--log-max-size', type=int, default=Config.DEFAULT_MAX_BYTES,
                          help=f'Max log file size in bytes (default: {Config.DEFAULT_MAX_BYTES}).')
    optional.add_argument('-c', '--log-backup-count', type=int, default=Config.DEFAULT_BACKUP_COUNT,
                          help=f'Number of backup log files (default: {Config.DEFAULT_BACKUP_COUNT}).')
    optional.add_argument('--transfer', action='store_true', help='Enable SFTP transfer.')
    optional.add_argument('--remote', type=parse_remote,
                          help='Remote destination (username@hostname[:directory]).')
    optional.add_argument('-i', '--identity-file', dest='identity_file',
                          type=lambda x: validate_file_path(x, check_readable=True),
                          help='Path to SSH private key file.')
    optional.add_argument('-p', '--ssh-port', type=validate_ssh_port, default=22,
                          help='SSH port (default: 22).')
    optional.add_argument('-q', '--quiet', action='store_true', help='Suppress non-error output.')
    optional.add_argument('-h', '--help', action='help', help='Show this help message.')
    try:
        args = parser.parse_args()
    except argparse.ArgumentError as e:
        print(f"Error: {str(e)}", file=sys.stderr)
        sys.exit(2)
    if len(sys.argv) == 1:
        print("Error: No arguments provided.", file=sys.stderr)
        print("Usage example:", file=sys.stderr)
        print("  python3 sma2ldif.py --alias-file aliases.txt --ldif-file output.ldif -d example.com", file=sys.stderr)
        print("  python3 sma2ldif.py --alias-file aliases.txt --ldif-file output.ldif -d example.com "
              "--transfer --remote user@host --identity-file ~/.ssh/id_rsa", file=sys.stderr)
        parser.print_help(sys.stderr)
        sys.exit(2)
    if args.transfer and not args.remote:
        print("Error: --remote is required when --transfer is used.", file=sys.stderr)
        sys.exit(2)
    return Args(
        input_file=args.input_file,
        output_file=args.output_file,
        domains=args.domains,
        groups=args.groups,
        expand_proxy=args.expand_proxy,
        log_level=args.log_level,
        log_file=args.log_file,
        log_max_size=args.log_max_size,
        log_backup_count=args.log_backup_count,
        transfer=args.transfer,
        remote=args.remote,
        identity_file=args.identity_file,
        ssh_port=args.ssh_port,
        quiet=args.quiet
    )


def main() -> None:
    """Convert Sendmail alias files to Proofpoint LDIF format and optionally transfer via SFTP."""
    try:
        args = parse_args()
    except SystemExit as e:
        sys.exit(e.code)

    try:
        setup_logging(args)
    except ValueError as e:
        print(f"Error: {str(e)}", file=sys.stderr)
        sys.exit(2)

    if not args.quiet:
        logging.info(f"Processing aliases from {args.input_file} to {args.output_file}")
        logging.info(f"Domains: {args.domains}")
        logging.info(f"Groups: {args.groups}")
        if args.transfer:
            remote_user, remote_host, remote_dir = args.remote
            logging.info(f"Transfer to {remote_user}@{remote_host}:{remote_dir or 'home directory'}")

    if not args.input_file.is_file():
        logging.error(f"Alias file {args.input_file} not found")
        sys.exit(1)

    # Initialize SFTP client and credentials
    sftp_client = None
    if args.transfer and args.remote:
        remote_user, remote_host, remote_dir = args.remote
        try:
            sftp_client = SFTPClient(remote_user, remote_host, args.ssh_port)
            if args.identity_file:
                # Use SSHKeyManager to load the key
                key_manager = SSHKeyManager(str(args.identity_file))
                passphrase = None
                if key_manager.needs_passphrase():
                    if args.quiet:
                        passphrase = os.environ.get('SMA2LDIF_KEY_PASSPHRASE')
                        if passphrase is None:
                            logging.error(
                                "Key passphrase required in quiet mode. Set SMA2LDIF_KEY_PASSPHRASE environment variable."
                            )
                            sys.exit(3)
                    else:
                        passphrase = getpass(f"Enter passphrase for SSH key {args.identity_file}: ")
                try:
                    private_key = key_manager.load(passphrase)
                except KeyValidationError as e:
                    logging.error(f"Failed to load SSH key {args.identity_file}: {str(e)}, details: {e.details}")
                    sys.exit(3)
                # Connect with key
                try:
                    sftp_client.connect_with_key(private_key)
                    if not args.quiet:
                        logging.info(f"Authenticated with SSH key for SFTP transfer to {remote_user}@{remote_host}")
                except AuthenticationError as e:
                    logging.error(f"Authentication failed: {str(e)}, details: {e.details}")
                    sftp_client.close()
                    sys.exit(3)
                except SFTPClientError as e:
                    logging.error(f"SSH connection error: {str(e)}, details: {e.details}")
                    sftp_client.close()
                    sys.exit(3)
            else:
                # Connect with password
                password = None
                if args.quiet:
                    password = os.environ.get('SMA2LDIF_PASSWORD')
                    if password is None:
                        logging.error(
                            "Password required in quiet mode. Set SMA2LDIF_PASSWORD environment variable."
                        )
                        sys.exit(3)
                else:
                    password = getpass(f"Enter SSH password for {remote_user}@{remote_host}: ")
                try:
                    sftp_client.connect_with_password(password)
                    if not args.quiet:
                        logging.info(f"Authenticated with password for SFTP transfer to {remote_user}@{remote_host}")
                except AuthenticationError as e:
                    logging.error(f"Authentication failed: {str(e)}, details: {e.details}")
                    sftp_client.close()
                    sys.exit(3)
                except SFTPClientError as e:
                    logging.error(f"SSH connection error: {str(e)}, details: {e.details}")
                    sftp_client.close()
                    sys.exit(3)
        except Exception as e:
            logging.error(f"Failed to initialize SFTP client: {str(e)}")
            sys.exit(3)

    # Process aliases and generate LDIF
    aliases = parse_aliases(args.input_file)
    if not aliases:
        logging.error("No aliases to process.")
        sys.exit(1)

    ldif_content = generate_pps_ldif(aliases, args.domains, args.groups, args.expand_proxy)
    if not ldif_content:
        logging.error("No LDIF content generated.")
        sys.exit(1)

    # Write LDIF file and transfer if requested
    try:
        write_ldif_file(ldif_content, args.output_file, args.quiet)
        if args.transfer and sftp_client:
            try:
                # Define progress callback for transfer
                def progress_callback(transferred: int, total: int) -> None:
                    if not args.quiet:
                        pbar.update(transferred - pbar.n)

                file_size = os.path.getsize(args.output_file)
                with tqdm(total=file_size, unit='B', unit_scale=True, desc="Transferring", disable=args.quiet) as pbar:
                    sftp_client.transfer_file(str(args.output_file), remote_dir, progress_callback=progress_callback)
                if not args.quiet:
                    logging.info(
                        f"Successfully transferred {args.output_file} to {remote_host}:{remote_dir or 'home directory'} via SFTP")
            except TransferError as e:
                logging.error(f"SFTP transfer failed: {str(e)}, details: {e.details}")
                sftp_client.close()
                sys.exit(1)
            except Exception as e:
                logging.error(f"Unexpected error during SFTP transfer: {str(e)}")
                sftp_client.close()
                sys.exit(1)
            finally:
                sftp_client.close()
    except RuntimeError as e:
        logging.error(f"Processing error: {str(e)}")
        if sftp_client:
            sftp_client.close()
        sys.exit(1)


if __name__ == "__main__":
    main()