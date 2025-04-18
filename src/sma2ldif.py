import argparse
import hashlib
import re
import logging
import sys

VALID_DOMAIN_REGEX = r"(?!-)[a-z0-9-]{1,63}(?<!-)(\.[a-z]{2,63}){1,2}$"

def is_valid_domain_syntax(domain_name: str):
    if not re.match(VALID_DOMAIN_REGEX, domain_name, re.IGNORECASE):
        raise argparse.ArgumentTypeError(f"Invalid domain name syntax: {domain_name}")
    return domain_name

def setup_logging():
    """Set up logging to file and console."""
    logging.basicConfig(
        level=logging.WARNING,
        format='%(asctime)s - %(levelname)s - %(message)s',
        handlers=[
            logging.FileHandler('alias_to_ldif.log'),
            logging.StreamHandler()
        ]
    )


def classify_target(target, aliases):
    """Classify the type of target."""
    target = target.strip()
    if target.startswith('"|') and target.endswith('"'):
        return 'command'
    elif target.startswith('|'):
        return 'command'
    elif target.startswith('/'):
        return 'file'
    elif target.startswith(':include:'):
        return 'include'
    elif '@' in target and re.match(r'^[^|]+@[\w\-\.]+$', target):
        return 'email'
    elif target in aliases:
        return 'alias'
    elif re.match(r'^[\w\-]+$', target):
        return 'local_user'
    else:
        return 'invalid'


def parse_aliases(file_path):
    """Parse a sendmail alias file into a dictionary."""
    aliases = {}
    current_alias = None
    current_target = []
    seen_aliases = set()

    def split_targets(target_str):
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
                # Remove trailing whitespace but preserve leading for continuation
                line = line.rstrip()
                if not line or line.startswith('#'):
                    continue

                # Check for continuation line (starts with whitespace)
                if line.startswith((' ', '\t')):
                    if current_alias:
                        current_target.append(line.lstrip())
                    else:
                        logging.warning(f"Continuation line ignored without alias: {line}")
                    continue

                # Process a new alias line
                match = re.match(r'^([^:]+):\s*(.*)$', line)
                if match:
                    # Store previous alias if exists
                    if current_alias:
                        target_str = ' '.join(current_target)
                        targets = split_targets(target_str)
                        if current_alias in seen_aliases:
                            logging.warning(f"Duplicate alias '{current_alias}' detected. Overwriting previous definition.")
                        aliases[current_alias] = targets
                        seen_aliases.add(current_alias)
                        current_target = []
                    # Start new alias
                    current_alias = match.group(1)
                    if current_alias != current_alias.lower():
                        logging.warning(f"Uppercase alias '{current_alias}' may cause issues with nested aliasing.")
                    if match.group(2):
                        current_target.append(match.group(2))
                else:
                    logging.warning(f"Invalid line skipped: {line}")

            # Store the last alias
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
    except Exception as e:
        logging.error(f"Failed to parse {file_path}: {str(e)}")
        return {}

    return aliases


def resolve_targets(targets, aliases, domain, visited=None):
    """Recursively resolve targets to emails or local users."""
    if visited is None:
        visited = set()

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
                sub_targets = resolve_targets(aliases[target], aliases, domain, visited.copy())
                resolved.extend(sub_targets)
            else:
                logging.warning(f"Alias '{target}' not found in alias map")
            visited.remove(target)
        elif target_type == 'include':
            file_path = target[len(':include:'):]
            try:
                with open(file_path, 'r') as f:
                    file_targets = [line.strip() for line in f if line.strip() and not line.startswith('#')]
                sub_targets = resolve_targets(file_targets, aliases, domain, visited.copy())
                resolved.extend(sub_targets)
            except FileNotFoundError:
                logging.warning(f"Include file '{file_path}' not found")
            except PermissionError:
                logging.warning(f"Permission denied accessing include file '{file_path}'")
            except Exception as e:
                logging.warning(f"Failed to read include file '{file_path}': {str(e)}")
        else:
            logging.warning(f"Skipping non-email target '{target}' ({target_type})")

    # Remove duplicates while preserving order
    seen = set()
    return [t for t in resolved if not (t in seen or seen.add(t))]


def generate_pps_ldif(aliases, domains, group="Sendmail_Aliases"):
    """Generate Proofpoint LDIF content from parsed and resolved aliases."""
    ldif_entries = []

    domain = domains.pop(0)

    for alias in sorted(aliases.keys()):
        alias_email = f"{alias}@{domain}"
        uid = hashlib.md5(alias_email.encode("utf-8")).hexdigest()

        entry = [
            f"dn: {uid}",
            f"uid: {uid}",
            f"givenName: {alias}",
            "profileType: 1",
            f"mail: {alias_email}",
        ]

        for pa in domains:
            entry.append(f"proxyAddresses: {alias}@{pa}")

        if group:
            entry.append(f"memberOf: {group}")

        entry.append("")

        ldif_entries.append("\n".join(entry))

    return "\n".join(ldif_entries)

def write_ldif_file(ldif_content, output_file):
    """Write LDIF content to a file."""
    try:
        with open(output_file, 'w') as f:
            f.write(ldif_content)
        logging.info(f"LDIF file written to {output_file}")
    except PermissionError:
        logging.error(f"Permission denied writing to {output_file}")
    except Exception as e:
        logging.error(f"Failed to write {output_file}: {str(e)}")


def main():
    parser = argparse.ArgumentParser(prog="sma2ldif",
                                     description="""Tool to Convert Sendmail Alias Files to Proofpoint LDIF Format""",
                                     formatter_class=lambda prog: argparse.HelpFormatter(prog, max_help_position=80))

    parser.add_argument('-i', '--input', metavar='<aliases>', dest="input_file", type=str, required=True,
                        help='LDIF to read as input.')
    parser.add_argument('-o', '--output', metavar='<ldif>', dest="output_file", type=str, required=True,
                        help='CSV file to create as output.')
    parser.add_argument('--domains', default=[], metavar='<domain>', dest="domains", required=True,
                              nargs='+', type=is_valid_domain_syntax, help='Alias domains from processing.')

    if len(sys.argv) == 1:
        parser.print_usage(sys.stderr)
        sys.exit(1)

    args = parser.parse_args()

    setup_logging()

    # Convert an aliases file to dictionary
    aliases = parse_aliases(args.input_file)

    if not aliases:
        logging.error("No aliases to process.")
        return

    for alias, targets in sorted(aliases.items()):
        logging.info(f"  {alias}: {targets}")

    ldif_content = generate_pps_ldif(aliases, args.domains)

    if ldif_content:
        write_ldif_file(ldif_content, args.output_file)
    else:
        logging.warning("No LDIF content generated.")

if __name__ == "__main__":
    main()