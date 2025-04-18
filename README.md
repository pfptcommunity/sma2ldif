# Simple tool to compare LDIF files
Tool to Convert Sendmail Alias Files to Proofpoint LDIF Format

### Requirements:

* Python 3.9+
 
### Installing the Package

You can install the tool using the following command directly from Github.

```
pip install git+https://github.com/pfptcommunity/sma2ldif.git
```

or can install the tool using pip.

```
# When testing on Ubuntu 24.04 the following will not work:
pip install sma2ldif
```

If you see an error similar to the following:

```
error: externally-managed-environment

× This environment is externally managed
╰─> To install Python packages system-wide, try apt install
    python3-xyz, where xyz is the package you are trying to
    install.

    If you wish to install a non-Debian-packaged Python package,
    create a virtual environment using python3 -m venv path/to/venv.
    Then use path/to/venv/bin/python and path/to/venv/bin/pip. Make
    sure you have python3-full installed.

    If you wish to install a non-Debian packaged Python application,
    it may be easiest to use pipx install xyz, which will manage a
    virtual environment for you. Make sure you have pipx installed.

    See /usr/share/doc/python3.12/README.venv for more information.

note: If you believe this is a mistake, please contact your Python installation or OS distribution provider. You can override this, at the risk of breaking your Python installation or OS, by passing --break-system-packages.
hint: See PEP 668 for the detailed specification.
```

You should use install pipx or you can configure your own virtual environment and use the command referenced above.

```
pipx install sma2ldif
```

### Usage

```
usage: sma2ldif [-h] -i <aliases> -o <ldif> -d <domain> [<domain> ...] [-g <group> [<group> ...]] [--log-level {debug,info,warning,error,critical}] [-l LOG_FILE] [-s LOG_MAX_SIZE] [-c LOG_BACKUP_COUNT]

Convert Sendmail alias files to Proofpoint LDIF format.

optional arguments:
  -h, --help                                                     show this help message and exit
  -i <aliases>, --input <aliases>                                Path to the input Sendmail aliases file.
  -o <ldif>, --output <ldif>                                     Path to the output LDIF file.
  -d <domain> [<domain> ...], --domains <domain> [<domain> ...]  List of domains for alias processing (first domain is primary).
  -g <group> [<group> ...], --groups <group> [<group> ...]       List of memberOf groups for alias processing.
  --log-level {debug,info,warning,error,critical}                Set the logging level (default: warning).
  -l LOG_FILE, --log-file LOG_FILE                               Set the log file location (default: sma2ldif.log).
  -s LOG_MAX_SIZE, --log-max-size LOG_MAX_SIZE                   Maximum size of log file in bytes before rotation (default: 10485760).
  -c LOG_BACKUP_COUNT, --log-backup-count LOG_BACKUP_COUNT       Number of backup log files to keep (default: 5).
```