"""
Module to perform NTLM-hashes dump functionality

Author:
    Konstantin S. (https://github.com/ST1LLY)
"""
import logging
import os
import subprocess
import sys

import modules.support_functions as sup_f
from enviroment import LOGS_DIR, DUMP_NTLM_SCRIPT_PATH


class DumpNTLMPerformer:
    """
    Class to perform dumping NTLM hashes functionality
    """

    instances: list = []

    def __init__(self) -> None:
        pass

    @staticmethod
    def __is_error(file_err_path: str) -> bool:
        if os.stat(file_err_path).st_size == 0:
            return False
        return True

    @staticmethod
    def __check_error_or_finished(file_out_path: str, file_err_path: str) -> dict:
        if 'NTLM-hashes dump file' in (last_line := sup_f.get_last_file_line(file_out_path)):
            return {'status': 'finished', 'err_desc': '', 'hashes_file_path': last_line.split(':')[-1].strip()}

        if DumpNTLMPerformer.__is_error(file_err_path):
            return {
                'status': 'error',
                'err_desc': f'Check file {file_err_path} for additional info',
                'hashes_file_path': '',
            }
        return {}

    @staticmethod
    def run_instance(target: str, just_dc_user: str | None) -> str:
        """
        Run the instance of bruting process

        Args:
            target (str): The format is [[domain/]username[:password]@]<targetName or address>
            just_dc_user (str | None): The specified AD user

        Returns:
            str: session name
        """
        session_name = sup_f.generate_uuid()
        file_out_path = os.path.join(LOGS_DIR, f'ntlm_dumping_{session_name}.log')
        file_err_path = os.path.join(LOGS_DIR, f'ntlm_dumping_{session_name}_errors.log')

        process_args = [sys.executable, DUMP_NTLM_SCRIPT_PATH, '--target', target, '--session-name', session_name]
        if just_dc_user is not None:
            process_args.extend(['--just-dc-user', just_dc_user])

        logging.info('Run dump ntlm process %s', process_args)

        # We should interact with the run process further and can't use with statement here
        # pylint: disable=R1732
        subprocess.Popen(
            process_args,
            stdout=open(file_out_path, 'w', encoding='utf-8'),
            stdin=subprocess.PIPE,
            stderr=open(file_err_path, 'w', encoding='utf-8'),
        )

        DumpNTLMPerformer.instances.append(
            {'session_name': session_name, 'file_out_path': file_out_path, 'file_err_path': file_err_path}
        )

        return session_name

    @classmethod
    def get_instance_status(cls, session_name: str) -> dict[str, str]:
        """

        Args:
            session_name (str): uuid of running job

        Returns:
            dict[str, str]:
                status: error/finished/running/interrupted
                err_desc: error description if status = 'error'
                hashes_file_path: path to file with NTLM-hashes if status = 'finished'
        """

        is_instance_found = False

        file_out_path = os.path.join(LOGS_DIR, f'ntlm_dumping_{session_name}.log')
        file_err_path = os.path.join(LOGS_DIR, f'ntlm_dumping_{session_name}_errors.log')

        if not (os.path.exists(file_out_path) or os.path.exists(file_err_path)):
            return {'status': 'not_found', 'err_desc': '', 'hashes_file_path': ''}

        for instance in DumpNTLMPerformer.instances:
            if instance['session_name'] == session_name:
                is_instance_found = True
                break

        if status := cls.__check_error_or_finished(file_out_path, file_err_path):
            return status

        if is_instance_found:
            return {'status': 'running', 'err_desc': '', 'hashes_file_path': ''}

        return {'status': 'interrupted', 'err_desc': '', 'hashes_file_path': ''}
