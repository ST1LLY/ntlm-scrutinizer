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
from flask_restplus import Namespace, Resource, fields
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

api = Namespace('ntlm-scr')

# Models for output responses

session_name_fields = api.model('SessionName', {
    'session_name': fields.String,
})

status_data_fields = api.model('StatusData', {
    'title': fields.String,
    'value': fields.String,
})

instance_info_fields = api.model('InstanceInfo', {
    'session_name': fields.String,
    'state': fields.String,
    'status_data': fields.List(fields.Nested(status_data_fields))
})

benchmark_status_fields = api.model('BenchmarkStatus', {
    'status': fields.String,
    'started': fields.String,
    'stopped': fields.String,
    'speeds': fields.List(fields.String)
})

bruted_creds_fields = api.model('BrutedCreds', {
    'status': fields.String,
    'creds': fields.List(fields.String),
})

re_run_session_fields = api.model('ReRunSession', {
    'status': fields.String,
    'session_name': fields.String,
})

run_instance_p = api.parser()
run_instance_p.add_argument('hash_file_name', location='form', required=True,
                            help='The hash file name in files/ntlm_hashes')
run_instance_p.add_argument('dictionary_file_name', location='form', required=True,
                            help='The dictionary file name in files/dictionaries')
run_instance_p.add_argument('rules_file_name', location='form', required=True,
                            help='The rules file name in files/rules')


@api.route('/run-instance',
           doc={'description': 'Run an instance of hashcat to brute NTLM-hashes'})
class RunInstance(Resource):
    @api.expect(run_instance_p)
    @api.response(200, 'Success', session_name_fields)
    def post(self) -> Tuple:
        logging.debug(f'request {request}')
        data = run_instance_p.parse_args()

        return {'session_name': HashcatPerformer().run_instance(
            hash_file_path=os.path.join(NTLM_HASHES_DIR, data['hash_file_name']),
            dictionary_file_path=os.path.join(HASHCAT_DICTIONARIES_DIR, data['dictionary_file_name']),
            rules_file_path=os.path.join(HASHCAT_RULES_DIR, data['rules_file_name'])
        )}, 200


re_run_instance_p = api.parser()
re_run_instance_p.add_argument('session_name', location='form', required=True,
                               help='Re-run a broken instance from the restore file if it exists')


@api.route('/re-run-instance',
           doc={'description': 'Re-run an instance of hashcat to brute NTLM-hashes if the restore file exists'})
class ReRunInstance(Resource):
    @api.expect(re_run_instance_p)
    @api.response(200, 'Success', re_run_session_fields)
    def post(self) -> Tuple:
        logging.debug(f'request {request}')
        data = re_run_instance_p.parse_args()

        return HashcatPerformer().re_run_instance(
            session_name=data['session_name']
        ), 200


instance_info_p = api.parser()
instance_info_p.add_argument('session_name', location='args', required=True,
                             help='The session name of instance')


@api.route('/instance-info',
           doc={'description': 'Get information about a running instance'})
class InstanceInfo(Resource):
    @api.expect(instance_info_p)
    @api.response(200, 'Success', instance_info_fields)
    def get(self) -> Tuple:
        logging.debug(f'request {request}')
        data = instance_info_p.parse_args()

        return {'instance_info': HashcatPerformer().get_instance_info(data['session_name'])}, 200


@api.route('/all-instances-info',
           doc={'description': 'Get information about all running instances'})
class AllInstancesInfo(Resource):
    @api.response(200, 'Success', fields.List(fields.Nested(instance_info_fields)))
    def get(self) -> Tuple:
        logging.debug(f'request {request}')

        return HashcatPerformer().get_all_instances_info(), 200


dump_and_brute_ntlm_p = api.parser()
dump_and_brute_ntlm_p.add_argument('target', location='form', required=True,
                                   help='The format is [[domain/]username[:password]@]<targetName or address>')
dump_and_brute_ntlm_p.add_argument('hashes', location='form', required=True,
                                   help='The NTLM hash (format is LMHASH:NTHASH)')
dump_and_brute_ntlm_p.add_argument('just_dc_user', location='form', required=False,
                                   help='The specified AD user')
dump_and_brute_ntlm_p.add_argument('dictionary_file_name', location='form', required=True,
                                   help='The dictionary file name in files/dictionaries')
dump_and_brute_ntlm_p.add_argument('rules_file_name', location='form', required=True,
                                   help='The rules file name in files/rules')


@api.route('/dump-and-brute-ntlm',
           doc={'description': 'Dump NTLM-hashes from AD and run an instance for bruting'})
class DumpAndBruteNtlm(Resource):
    @api.expect(dump_and_brute_ntlm_p)
    @api.response(200, 'Success', session_name_fields)
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


@api.route('/run-benchmark',
           doc={'description': 'Run benchmark for bruting'})
class RunBenchmark(Resource):
    @api.response(200, 'Success', benchmark_status_fields)
    def get(self) -> Tuple:
        logging.debug(f'request {request}')

        return HashcatPerformer().run_benchmark(), 200


bruted_creds_p = api.parser()
bruted_creds_p.add_argument('session_name', location='args', required=True,
                            help='The session name of a run instance')


@api.route('/bruted-creds',
           doc={'description': 'Get bruted credentials'})
class BrutedCreads(Resource):
    @api.expect(bruted_creds_p)
    @api.response(200, 'Success', bruted_creds_fields)
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
