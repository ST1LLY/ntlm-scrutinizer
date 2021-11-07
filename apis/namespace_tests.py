"""
Using functionality via Swagger

Author:
    Konstantin S. (https://github.com/ST1LLY)
"""
import os
import logging
from typing import Tuple
import time

from modules.hashcat_performer import HashcatPerformer
from modules.dump_secrets_ntlm import DumpSecretsNtlm
import modules.support_functions as sup_f

from flask import request
from flask_restplus import Namespace, Resource
from enviroment import LOGS_DIR, \
    HASHCAT_RESTORES_DIR, \
    HASHCAT_BRUTED_HASHES_DIR, \
    HASHCAT_DICTIONARIES_DIR, \
    HASHCAT_RULES_DIR, \
    NTLM_HASHES_DIR

HashcatPerformer().set_working_folders(
    output_folder=HASHCAT_BRUTED_HASHES_DIR,
    restores_folder=HASHCAT_RESTORES_DIR,
    logs_folder=LOGS_DIR)

api = Namespace('tests', description='Tests API')

run_instance_p = api.parser()
run_instance_p.add_argument('hash_file_name', location='form', required=True,
                            help='hash file name in files/ntlm_hashes directory', default='all_users.ntds')
run_instance_p.add_argument('dictionary_file_name', location='form', required=True,
                            help='dictionary file name in files/dictionaries directory', default='rockyou.txt')
run_instance_p.add_argument('rules_file_name', location='form', required=True,
                            help='rules file name in files/rules directory', default='InsidePro-PasswordsPro.rule')


@api.route('/run-instance')
class RunInstance(Resource):
    @api.expect(run_instance_p)
    def post(self) -> Tuple:
        logging.debug(f'request {request}')
        data = run_instance_p.parse_args()

        return {'session_name': HashcatPerformer().run_instance(
            hash_file_path=os.path.join(NTLM_HASHES_DIR, data['hash_file_name']),
            dictionary_file_path=os.path.join(HASHCAT_DICTIONARIES_DIR, data['dictionary_file_name']),
            rules_file_path=os.path.join(HASHCAT_RULES_DIR, data['rules_file_name']),
            # session_name='test_restoring'
        )}, 200


instance_info_p = api.parser()
instance_info_p.add_argument('session_name', location='args', required=True,
                             help='session name of instance')


@api.route('/instance-info')
class InstanceInfo(Resource):
    @api.expect(instance_info_p)
    def get(self) -> Tuple:
        logging.debug(f'request {request}')
        data = instance_info_p.parse_args()

        return {'instance_info': HashcatPerformer().get_instance_info(data['session_name'])}, 200


@api.route('/all-instances-info')
class AllInstancesInfo(Resource):
    def get(self) -> Tuple:
        logging.debug(f'request {request}')

        return HashcatPerformer().get_all_instances_info(), 200


dump_and_brute_ntlm_p = api.parser()
dump_and_brute_ntlm_p.add_argument('target', location='form', required=True,
                                   help='[[domain/]username[:password]@]<targetName or address>')
dump_and_brute_ntlm_p.add_argument('hashes', location='form', required=True,
                                   help='NTLM hashes, format is LMHASH:NTHASH')
dump_and_brute_ntlm_p.add_argument('just_dc_user', location='form', required=False,
                                   help='Specified user from AD')
dump_and_brute_ntlm_p.add_argument('dictionary_file_name', location='form', required=True,
                                   help='dictionary file name in files/dictionaries directory', default='rockyou.txt')
dump_and_brute_ntlm_p.add_argument('rules_file_name', location='form', required=True,
                                   help='rules file name in files/rules directory',
                                   default='InsidePro-PasswordsPro.rule')


@api.route('/dump-and-brute-ntlm')
class DumpAndBruteNtlm(Resource):
    @api.expect(dump_and_brute_ntlm_p)
    def post(self) -> Tuple:
        logging.debug(f'request {request}')
        data = dump_and_brute_ntlm_p.parse_args()

        if data['just_dc_user'] is None:
            logging.info('Getting hashes from all users')
            dump_secrets_ntlm = DumpSecretsNtlm(target=data['target'],
                                                hashes=data['hashes'],
                                                output_file=os.path.join(NTLM_HASHES_DIR,
                                                                         f"{time.strftime('%Y_%m_%d__%H_%M_%S.%f')}"
                                                                         "_all_users"))
        else:
            logging.info(f"Getting hashes from the certain user {data['just_dc_user']}")
            dump_secrets_ntlm = DumpSecretsNtlm(target=data['target'],
                                                hashes=data['hashes'],
                                                just_dc_user=data['just_dc_user'],
                                                output_file=os.path.join(NTLM_HASHES_DIR,
                                                                         f"{time.strftime('%Y_%m_%d__%H_%M_%S.%f')}"
                                                                         f"_{data['just_dc_user']}"))
        hash_file_path = dump_secrets_ntlm.get_ntlm_hashes()
        logging.info(f"Gotten hashes have been dumped to {hash_file_path}")

        return {'session_name': HashcatPerformer().run_instance(
            hash_file_path=hash_file_path,
            dictionary_file_path=os.path.join(HASHCAT_DICTIONARIES_DIR, data['dictionary_file_name']),
            rules_file_path=os.path.join(HASHCAT_RULES_DIR, data['rules_file_name']),
        )}, 200


@api.route('/run-benchmark')
class RunBenchmark(Resource):
    def get(self) -> Tuple:
        logging.debug(f'request {request}')

        return HashcatPerformer().run_benchmark(), 200


bruted_creds_p = api.parser()
bruted_creds_p.add_argument('session_name', location='args', required=True,
                            help='session_name of a run instance')


@api.route('/bruted-creds')
class BrutedCreads(Resource):
    @api.expect(bruted_creds_p)
    def get(self) -> Tuple:
        logging.debug(f'request {request}')
        data = bruted_creds_p.parse_args()

        # Trying to find the output file with bruted hashes
        bruted_hashes_file_path = sup_f.try_find_file_in_dir(HASHCAT_BRUTED_HASHES_DIR, data['session_name'])

        if bruted_hashes_file_path is None:
            logging.error(
                f"The bruted hashes file for session_name: {data['session_name']} in "
                f"{HASHCAT_BRUTED_HASHES_DIR} not found")

            return {
                       'status': 'not_found',
                       'creds': []
                   }, 200

        splitted_file_name = os.path.basename(bruted_hashes_file_path).split('___')

        if len(splitted_file_name) != 2:
            logging.error(
                f"The file name of file {bruted_hashes_file_path} couldn't been splitted to 2 part by '___'")
            return {
                       'status': 'not_found',
                       'creds': []
                   }, 200

        # Trying to find used file contained ntlm hashes for this session
        ntlm_hashes_file_path = sup_f.try_find_file_in_dir(NTLM_HASHES_DIR, splitted_file_name[0])

        if ntlm_hashes_file_path is None:
            logging.error(
                f"The used file contained ntlm hashes for session_name: {data['session_name']} in "
                f"{NTLM_HASHES_DIR} not found")

            return {
                       'status': 'not_found',
                       'creds': []
                   }, 200

        bruted_hashes = sup_f.read_file_to_lst(bruted_hashes_file_path)
        ntlm_hashes = sup_f.read_file_to_lst(ntlm_hashes_file_path)

        # Matching bruted hashes with ntlm hashes
        creads = []
        for bruted_hash in bruted_hashes:
            hash_v, password = tuple(bruted_hash.split(':'))
            for ntlm_hash in ntlm_hashes:
                if hash_v in ntlm_hash:
                    creads.append(
                        f"{ntlm_hash.split(':')[0]}:{password}"
                    )
        logging.info(f"Got {len(creads)} creds for session_name: {data['session_name']}")
        if not creads:
            return {
                       'status': 'not_found',
                       'creds': []
                   }, 200

        return {
                   'status': 'found',
                   'creds': creads
               }, 200
