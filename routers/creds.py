import logging
import os
from enum import Enum

from fastapi import APIRouter, Depends
from pydantic import BaseModel, Field
from uuid import UUID
import modules.support_functions as sup_f
from enviroment import (
    LOGS_DIR,
    HASHCAT_RESTORES_DIR,
    HASHCAT_BRUTED_HASHES_DIR,
    NTLM_HASHES_DIR,
)
from modules.hashcat_performer import HashcatPerformer
from .common import common_query_session_params

HashcatPerformer().set_working_folders(
    output_folder=HASHCAT_BRUTED_HASHES_DIR, restores_folder=HASHCAT_RESTORES_DIR, logs_folder=LOGS_DIR
)

router = APIRouter(
    prefix='/creds',
    tags=['creds'],
)


class CredsStatus(str, Enum):
    found = 'found'
    not_found = 'not_found'


class BrutedAcc(BaseModel):
    login: str = Field(default=..., title='The login of a bruted acc')
    password: str = Field(default=..., title='The password of a bruted acc')


class BrutedCredsData(BaseModel):
    status: CredsStatus = Field(default=..., title='The status of bruted accs')
    creds: list[BrutedAcc] = Field(default=..., title='The list of bruted accs')


@router.get(
    '/bruted',
    description='Get bruted credentials',
    response_model=BrutedCredsData,
)
def bruted(commons: dict[str, UUID] = Depends(common_query_session_params)) -> dict[str, str | list[dict[str, str]]]:

    # Trying to find the output file with bruted hashes
    bruted_hashes_file_path = sup_f.try_find_file_in_dir(HASHCAT_BRUTED_HASHES_DIR, str(commons['session_name']))

    if bruted_hashes_file_path is None:
        logging.error(
            f"The bruted hashes file for session_name: {commons['session_name']} in "
            f'{HASHCAT_BRUTED_HASHES_DIR} not found'
        )

        return {'status': 'not_found', 'creds': []}

    splitted_file_name = os.path.basename(bruted_hashes_file_path).split('___')

    if len(splitted_file_name) != 2:
        logging.error(f"The file name of file {bruted_hashes_file_path} couldn't been splitted to 2 part by '___'")
        return {'status': 'not_found', 'creds': []}

    # Trying to find used file contained ntlm hashes for this session
    ntlm_hashes_file_path = sup_f.try_find_file_in_dir(NTLM_HASHES_DIR, splitted_file_name[0])

    if ntlm_hashes_file_path is None:
        logging.error(
            f"The used file contained ntlm hashes for session_name: {commons['session_name']} in "
            f'{NTLM_HASHES_DIR} not found'
        )

        return {'status': 'not_found', 'creds': []}

    bruted_hashes = sup_f.read_file_to_lst(bruted_hashes_file_path)
    ntlm_hashes = sup_f.read_file_to_lst(ntlm_hashes_file_path)

    # Matching bruted hashes with ntlm hashes
    creads = []
    for bruted_hash in bruted_hashes:
        hash_v, password = tuple(bruted_hash.split(':'))
        for ntlm_hash in ntlm_hashes:
            if hash_v in ntlm_hash:
                creads.append({'login': ntlm_hash.split(':')[0], 'password': password})
    logging.info(f"Got {len(creads)} creds for session_name: {commons['session_name']}")
    if not creads:
        return {'status': 'not_found', 'creds': []}

    return {'status': 'found', 'creds': creads}
