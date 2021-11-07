"""
Module to perform hashcat functionality

Author:
    Konstantin S. (https://github.com/ST1LLY)
"""
import os
import subprocess
import logging
import uuid
import re

from typing import List

import modules.support_functions as sup_f
import time


class NotAllowedFileName(Exception):
    """
    Raise when restrictions for file names occurred
    """
    pass


class HashcatPerformer:
    """
    Class to perform hashcat functionality
    """
    instances: list = []
    output_folder: str
    restores_folder: str
    logs_folder: str

    def __init__(self) -> None:
        pass

    @staticmethod
    def __set_instance(instance: dict) -> None:
        """
        Set new instance to managed list

        Args:
            instance (dict): dict with info of new instance
        """
        HashcatPerformer.instances.append(instance)

    @staticmethod
    def __get_found_instance_info(certain_instance: dict) -> dict:
        """
        Info about the found instance of hashcat.
        Check on existence by session name has been done before.

        Args:
            certain_instance (dict): found instance of hashcat

        Returns:
            dict:   {
                        'session_name': the session name,
                        'state': 'found' / 'undefined',
                        'status_data': empty list if the state is 'undefined',
                                        otherwise list of values from
                                        hashcat status output
                    }
        """
        # Performing '[s]tatus' option during the execution of the process
        proc = certain_instance['subprocess']

        # If the subprocess is running
        if proc.poll() is None:
            proc.stdin.write(b's\n')
            proc.stdin.flush()
            # Pause for waiting for log output file filling
            time.sleep(0.05)

        # Getting last rest of log output file
        stdout = sup_f.read_file_to_lst(certain_instance['file_out_path'])[-40:]

        # Searching a beginning of the part in stdout about performing status
        start_i = None
        for i, line in reversed(list(enumerate(stdout))):
            if 'Session...' in line:
                start_i = i
                break

        # The part containing info about performing status hasn't been found
        if start_i is None:
            return {
                'session_name': certain_instance['session_name'],
                'state': 'undefined',
                'status_data': []
            }

        # Collecting information about performing status
        status_data = []
        for line in stdout[start_i:]:

            # Checking the ending of the status block
            if line == '':
                break

            splited = line.split('.:')
            if len(splited) != 2:
                logging.warning(f"line: {repr(line)} hasn't been splitted to two part")
                continue
            status_data.append({
                'title': splited[0].strip('. \t\n\r'),
                'value': splited[1].strip(' \t\n\r')
            })

        return {
            'session_name': certain_instance['session_name'],
            'state': 'found',
            'status_data': status_data
        }

    @staticmethod
    def set_working_folders(output_folder: str, restores_folder: str, logs_folder: str) -> None:
        """
        Set working folders for class

        Args:
            output_folder (str): path to folder contained output files
            restores_folder (str): path to folder contained restores files
            logs_folder (str): path to folder contained logs files
        """
        HashcatPerformer.output_folder = output_folder
        HashcatPerformer.restores_folder = restores_folder
        HashcatPerformer.logs_folder = logs_folder

    @staticmethod
    def get_instance_info(session_name: str) -> dict:
        """
        Info about run instance of hashcat

        Args:
            session_name (str): session_name of hashcat

        Returns:
            dict:   {
                        'session_name': the session name,
                        'state': 'not_found' / 'found' / 'undefined',
                        'status_data':  empty list if the state is 'not_found'
                                        or 'undefined', otherwise list of
                                        values from hashcat status output
                        }
        """
        # Searching the instance in running instances
        certain_instance = {}
        for instance in HashcatPerformer.instances:
            if instance['session_name'] == session_name:
                certain_instance = instance
                break

        # The instance hasn't been found
        if not certain_instance:
            return {
                'session_name': session_name,
                'state': 'not_found',
                'status_data': []
            }

        return HashcatPerformer.__get_found_instance_info(certain_instance)

    @staticmethod
    def get_all_instances_info() -> List[dict]:
        """
        Get info about all run instances of hashcat

        Returns:
            List[dict]: Info about all run instances
        """

        # Gathering info about all run instances of hashcat
        instances_info = []
        for instance in HashcatPerformer.instances:
            instances_info.append(HashcatPerformer.__get_found_instance_info(instance))

        return instances_info

    @staticmethod
    def run_instance(hash_file_path: str,
                     dictionary_file_path: str,
                     rules_file_path: str,
                     session_name: str = None,
                     is_force: bool = True) -> str:
        """
        Run instance of hashcat

        Args:
            hash_file_path (str): path to file contained hashes
            dictionary_file_path (str): path to file contained dictionary
            rules_file_path (str): path to file contained rules
            session_name (str): name for hascat session. Default: None
            is_force (bool): run hascat with --force flag. Default: True


        Returns:
            str: name for hascat session

        Raises:
            NotAllowedFileName: session_name or/and hash filename contains
                                not allowed filename
        """

        # If the session name hasn't been given then generating a unique session name
        if session_name is None:
            session_name = str(uuid.uuid4())

        # Implementing run command
        restore_file_path = os.path.join(HashcatPerformer.restores_folder, f'{session_name}.restore')

        # Checking if the restore file for the session exists
        if os.path.isfile(restore_file_path):
            # This restore file exists
            process_args = [
                'hashcat',
                '--restore',
                f'--restore-file-path={restore_file_path}'
            ]
        else:
            # This restore file doesn't exist
            hash_file_name = os.path.basename(hash_file_path)

            # Checking restrictions for names
            if '___' in session_name:
                raise NotAllowedFileName(f"Name {session_name} of session can't contained '___'")

            if '___' in hash_file_name:
                raise NotAllowedFileName(f"Name {hash_file_name} of file with hashes can't contained '___'")

            process_args = [
                'hashcat',
                '-m',
                '1000',
                hash_file_path,
                dictionary_file_path,
                '-r',
                rules_file_path,
                f'--session={session_name}',
                '--restore-file-path=' + restore_file_path,
                '-o',
                os.path.join(HashcatPerformer.output_folder,
                             f'{hash_file_name}___{session_name}.txt'),
                '--potfile-disable',
                '--force' if is_force else ''
            ]
        logging.info(f'Running subprocess: {process_args}')

        file_out_path = os.path.join(HashcatPerformer.logs_folder, f'hashcat_{session_name}.log')
        file_err_path = os.path.join(HashcatPerformer.logs_folder, f'hashcat_{session_name}_errors.log')

        p = subprocess.Popen(process_args,
                             stdout=open(file_out_path, 'w'),
                             stdin=subprocess.PIPE,
                             stderr=open(file_err_path, 'w'))

        HashcatPerformer.__set_instance({
            'session_name': session_name,
            'subprocess': p,
            'file_out_path': file_out_path,
            'file_err_path': file_err_path
        })

        logging.info(f'Subprocess started with session_name: {session_name}')
        return session_name

    @staticmethod
    def run_benchmark(is_force: bool = True) -> dict:
        """
        Run hashcat -b -m 1000

        Args:
            is_force (bool): run hascat with --force flag. Default: True

        Returns:
            dict: {
                'status': 'success' / 'error'
                'started': time of starting benchmark
                'started': time of ending benchmark
                'speeds': list of measures of speeds
            }
        """

        process_args = [
            'hashcat',
            '-b',
            '-m',
            '1000',
            '--force' if is_force else ''
        ]

        # Running a benchmark process
        result = subprocess.run(process_args,
                                stdout=subprocess.PIPE,
                                stderr=subprocess.PIPE)

        # Getting output of the process
        out = result.stdout.decode('utf-8')
        err = result.stderr.decode('utf-8')

        logging.info(f'out: {out}')

        # Getting started and stopped times of the benchmark
        started_s = re.search(r'Started: (.+)', out, re.MULTILINE)
        stopped_s = re.search(r'Stopped: (.+)', out, re.MULTILINE)

        started = started_s.group(1) if started_s is not None else ''
        stopped = stopped_s.group(1) if stopped_s is not None else ''

        # If an error has occurred during the benchmark
        if err:
            logging.error(f'err: {err}')

            return {
                'status': 'error',
                'started': started,
                'stopped': stopped,
                'speeds': [],
            }

        # Getting information about speeds
        speeds = re.findall(r'(?<=\.\.:)\s+(.+)', out)

        return {
            'status': 'success',
            'started': started,
            'stopped': stopped,
            'speeds': speeds,
        }
