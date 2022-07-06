"""
Shared environment constants for app
"""
import os
import modules.support_functions as sup_f

# Get this file full path
ROOT_DIR = os.path.dirname(os.path.abspath(__file__))

# To initialize paths to directories
LOGS_DIR = os.path.join(ROOT_DIR, 'files', 'logs')

# The path to the dir with hashcat restore files
HASHCAT_RESTORES_DIR = os.path.join(ROOT_DIR, 'files', 'restores')

# The path to the dir with bruted hashes
HASHCAT_BRUTED_HASHES_DIR = os.path.join(ROOT_DIR, 'files', 'bruted_hashes')

# The path to the dir with brute dictionaries
HASHCAT_DICTIONARIES_DIR = os.path.join(ROOT_DIR, 'files', 'dictionaries')

# The path to the dir with brute rules
HASHCAT_RULES_DIR = os.path.join(ROOT_DIR, 'files', 'rules')

# The path to the dir with ntlm hashes
NTLM_HASHES_DIR = os.path.join(ROOT_DIR, 'files', 'ntlm_hashes')

DUMP_NTLM_SCRIPT_PATH = os.path.join(ROOT_DIR, 'dump_secrets_ntlm.py')

# The path to app config file
CONFIG_PATH = os.path.join(ROOT_DIR, 'configs', 'settings.conf')
APP_CONFIG = sup_f.get_config(CONFIG_PATH, 'APP')
print(APP_CONFIG)
