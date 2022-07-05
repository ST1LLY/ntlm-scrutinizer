import datetime
import logging
import os
from enum import Enum
from uuid import UUID

from fastapi import APIRouter, Depends
from pydantic import BaseModel, Field

from enviroment import (
    LOGS_DIR,
    HASHCAT_RESTORES_DIR,
    HASHCAT_BRUTED_HASHES_DIR,
    HASHCAT_DICTIONARIES_DIR,
    HASHCAT_RULES_DIR,
    NTLM_HASHES_DIR,
)
from modules.dump_secrets_ntlm import DumpSecretsNtlm
from modules.hashcat_performer import HashcatPerformer
from .common import common_query_session_params

HashcatPerformer().set_working_folders(
    output_folder=HASHCAT_BRUTED_HASHES_DIR, restores_folder=HASHCAT_RESTORES_DIR, logs_folder=LOGS_DIR
)

router = APIRouter(
    prefix='/instance',
    tags=['instance'],
)


class SessionData(BaseModel):
    session_name: str = Field(default=..., title='The session name of run hashcat instance')


class ReRunSessionStatus(str, Enum):
    success = 'success'
    not_found = 'not_found'


class ReRunSessionParams(SessionData):
    status: ReRunSessionStatus = Field(default=..., title='The status of the re-running session')


class DumpAndRunParams(BaseModel):
    target: str = Field(default=..., title='The format is [[domain/]username[:password]@]<targetName or address>')
    dictionary_file_name: str = Field(default='rockyou.txt', title='The dictionary file name in files/dictionaries')
    rules_file_name: str = Field(default='InsidePro-PasswordsPro.rule', title='The rules file name in files/rules')
    just_dc_user: str | None = Field(default=None, title='The specified AD user')


class InstanceInfoState(str, Enum):
    found = 'found'
    not_found = 'not_found'
    undefined = 'undefined'


class InstanceInfoStatusFields(BaseModel):
    title: str = Field(default=..., title='The name of an output attr')
    value: str = Field(default=..., title='The value of an output attr')


class InstanceInfoData(SessionData):
    state: InstanceInfoState = Field(default=..., title='The state of the hashcat instance')
    status_data: list[InstanceInfoStatusFields] = Field(
        default=..., title='The list of values from hashcat status output'
    )


@router.post(
    '/dump-and-run', description='Dump NTLM-hashes from AD and run an instance for bruting', response_model=SessionData
)
def dump_and_run(data: DumpAndRunParams) -> dict[str, str]:
    if data.just_dc_user is None:
        logging.info('Getting hashes from all users')
        output_file = os.path.join(
            NTLM_HASHES_DIR, f"{datetime.datetime.now().strftime('%Y_%m_%d__%H_%M_%S.%f')}" f'_all_users'
        )
    else:
        logging.info(f'Getting hashes from the certain user {data.just_dc_user}')
        output_file = os.path.join(
            NTLM_HASHES_DIR, f"{datetime.datetime.now().strftime('%Y_%m_%d__%H_%M_%S.%f')}" f'_{data.just_dc_user}'
        )

    dump_secrets_ntlm = DumpSecretsNtlm(target=data.target, output_file=output_file, just_dc_user=data.just_dc_user)
    hash_file_path = dump_secrets_ntlm.get_ntlm_hashes()
    logging.info(f'Gotten hashes have been dumped to {hash_file_path}')

    return {
        'session_name': HashcatPerformer().run_instance(
            hash_file_path=hash_file_path,
            dictionary_file_path=os.path.join(HASHCAT_DICTIONARIES_DIR, data.dictionary_file_name),
            rules_file_path=os.path.join(HASHCAT_RULES_DIR, data.rules_file_name),
        )
    }


@router.post(
    '/re-run',
    description='Re-run an instance of hashcat to brute NTLM-hashes if the restore file exists',
    response_model=ReRunSessionParams,
)
def re_run(commons: dict[str, UUID] = Depends(common_query_session_params)) -> dict[str, str]:
    return HashcatPerformer().re_run_instance(session_name=str(commons['session_name']))


@router.get(
    '/info',
    description='Get information about a running instance',
    response_model=InstanceInfoData,
)
def info(commons: dict[str, UUID] = Depends(common_query_session_params)) -> dict[str, str]:
    return HashcatPerformer().get_instance_info(session_name=str(commons['session_name']))


@router.get(
    '/info-all',
    description='Get information about all running instances',
    response_model=list[InstanceInfoData],
)
def info_all() -> list[dict[str, str | list[dict[str, str]]]]:
    return HashcatPerformer().get_all_instances_info()
