"""
Wrapper around DumpSecrets

Author:
    Konstantin S. (https://github.com/ST1LLY)
"""

import argparse
import logging
import sys
import os
import re
from typing import Tuple, Any

from enviroment import NTLM_HASHES_DIR
from modules.dump_secrets import DumpSecrets


def parse_target(target: str) -> Tuple[str, str, str, str]:
    """Helper function to parse target information. The expected format is:

    <DOMAIN></USERNAME><:PASSWORD>@HOSTNAME

    Source:
        https://github.com/SecureAuthCorp/impacket/blob/master/impacket/examples/utils.py

    :param target: target to parse
    :type target: string

    :return: tuple of domain, username, password and remote name or IP address
    :rtype: (string, string, string, string)
    """
    # Regular expression to parse target information
    match_pattern = r'(?:(?:([^/@:]*)/)?([^@:]*)(?::([^@]*))?@)?(.*)'
    target_regex = re.compile(match_pattern)
    matched_result = target_regex.match(target)

    if matched_result is None:
        raise Exception(f'{target} is wrong! It must be according with pattern: {match_pattern}')

    domain, username, password, remote_name = matched_result.groups('')

    # In case the password contains '@'
    if '@' in remote_name:
        password = password + '@' + remote_name.rpartition('@')[0]
        remote_name = remote_name.rpartition('@')[2]

    return domain, username, password, remote_name


class Options(object):
    """
    Source:
        https://stackoverflow.com/a/2466207
    """

    def __init__(self, *initial_data: Any, **kwargs: Any):
        for dictionary in initial_data:
            for key in dictionary:
                setattr(self, key, dictionary[key])
        for key in kwargs:
            setattr(self, key, kwargs[key])


class DumpSecretsNtlm(DumpSecrets):
    def __init__(self, target: str, output_file: str, hashes: str = None, just_dc_user: str = None):
        """
        Class for dumping ntlm-hashes

        Args:
            target (str): [[domain/]username[:password]@]<targetName or address>
            output_file (str): base output filename. Extensions will be added for sam, secrets, cached and ntds
            hashes (str): NTLM hash, format is LMHASH:NTHASH. Default: None
            just_dc_user (str): Extract only NTDS.DIT data for the user specified. Default: None
        """
        domain, username, password, remote_name = parse_target(target)
        self.__options = Options(
            dict(
                aesKey=None,
                bootkey=None,
                dc_ip=None,
                debug=False,
                exec_method='smbexec',
                hashes=hashes,
                history=False,
                just_dc=True,
                just_dc_ntlm=True,
                just_dc_user=just_dc_user,
                k=False,
                keytab=None,
                no_pass=False,
                ntds=None,
                outputfile=output_file,
                pwd_last_set=False,
                resumefile=None,
                sam=None,
                security=None,
                system=None,
                target=target,
                target_ip=remote_name,
                ts=False,
                use_vss=False,
                user_status=False,
            )
        )

        DumpSecrets.__init__(self, domain, username, password, remote_name, self.__options)

    def get_ntlm_hashes(self) -> str:
        """
        Get ntlm-hash(es) and save into the output file

        Return:
            str: dumped file path
        """
        self.dump()
        extensions = ['.ntds', '.ntds.kerberos', '.ntds.cleartext']

        # NTDSHashes creates file with extension in auto way, so it's needed to check it
        for ext in extensions:
            file_path = self.__options.__getattribute__('outputfile') + ext
            if os.path.isfile(file_path):
                return file_path
        raise Exception("Dumped file hasn't found")


parser = argparse.ArgumentParser(
    description='NTLM-hashes dumper', formatter_class=argparse.ArgumentDefaultsHelpFormatter
)
parser.add_argument('--target', help='[[domain/]username[:password]@]<targetName or address>', type=str, required=True)
parser.add_argument('--session-name', help='Unic session name', type=str, required=True)
parser.add_argument(
    '--just-dc-user', help='Extract only NTDS.DIT data for the user specified', required=False, type=str, default=None
)


if __name__ == '__main__':
    root = logging.getLogger()
    root.setLevel(logging.INFO)

    handler = logging.StreamHandler(sys.stdout)
    handler.setLevel(logging.INFO)
    formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
    handler.setFormatter(formatter)
    root.addHandler(handler)

    args = parser.parse_args()

    output_file = os.path.join(NTLM_HASHES_DIR, args.session_name)

    dump_secrets_ntlm = DumpSecretsNtlm(target=args.target, output_file=output_file, just_dc_user=args.just_dc_user)
    hashes_file_path = dump_secrets_ntlm.get_ntlm_hashes()
    logging.info('Finished')
    logging.info(f'NTLM-hashes dump file: {hashes_file_path}')
