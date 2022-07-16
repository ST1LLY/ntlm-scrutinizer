"""
The module contains routers for NTLM bruting logic

Author:
    Konstantin S. (https://github.com/ST1LLY)
"""
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
)  # pylint: disable=import-error
from modules.hashcat_performer import HashcatPerformer  # pylint: disable=import-error
from .common import common_query_session_params

HashcatPerformer().set_working_folders(
    output_folder=HASHCAT_BRUTED_HASHES_DIR, restores_folder=HASHCAT_RESTORES_DIR, logs_folder=LOGS_DIR
)

router = APIRouter(
    prefix='/brute-ntlm',
    tags=['brute-ntlm'],
)


class BruteNTLMSessionData(BaseModel):
    """
    Minimal session info
    """

    session_name: str = Field(default=..., title='The session name of run hashcat instance')


class ReRunBruteNTLMSessionStatus(str, Enum):
    """
    The values of status field in the information of re-run brute process
    """

    SUCCESS = 'success'
    NOT_FOUND = 'not_found'


class ReRunBruteNTLMSessionData(BruteNTLMSessionData):
    """
    The information of the re-running NTLM bruting session
    """

    status: ReRunBruteNTLMSessionStatus = Field(default=..., title='The status of the re-running session')


class RunParams(BaseModel):
    """
    The params for running NTLM bruting session
    """

    hash_file_path: str = Field(default=..., title='The full path of file in files/ntlm_hashes')
    dictionary_file_name: str = Field(default='rockyou.txt', title='The dictionary file name in files/dictionaries')
    rules_file_name: str = Field(default='InsidePro-PasswordsPro.rule', title='The rules file name in files/rules')


class BruteNTLMInstanceInfoState(str, Enum):
    """
    The values of state field in the information of bruting process
    """

    FOUND = 'found'
    NOT_FOUND = 'not_found'
    UNDEFINED = 'undefined'


class BruteNTLMInstanceInfoStatusFields(BaseModel):
    """
    The fields of status bruting process from hashcat output
    """

    title: str = Field(default=..., title='The name of an output attr')
    value: str = Field(default=..., title='The value of an output attr')


class BruteNTLMInstanceInfoData(BruteNTLMSessionData):
    """
    The information of NTLM bruting session
    """

    state: BruteNTLMInstanceInfoState = Field(default=..., title='The state of the hashcat instance')
    status_data: list[BruteNTLMInstanceInfoStatusFields] = Field(
        default=..., title='The list of values from hashcat status output'
    )


@router.post(
    '/run', description='Dump NTLM-hashes from AD and run an instance for bruting', response_model=BruteNTLMSessionData
)
def run(data: RunParams) -> dict[str, str]:
    """
    See the description param of router decorator
    """
    return {
        'session_name': HashcatPerformer().run_instance(
            hash_file_path=data.hash_file_path,
            dictionary_file_path=os.path.join(HASHCAT_DICTIONARIES_DIR, data.dictionary_file_name),
            rules_file_path=os.path.join(HASHCAT_RULES_DIR, data.rules_file_name),
        )
    }


@router.post(
    '/re-run',
    description='Re-run an instance of hashcat to brute NTLM-hashes if the restore file exists',
    response_model=ReRunBruteNTLMSessionData,
)
def re_run(commons: dict[str, UUID] = Depends(common_query_session_params)) -> dict[str, str]:
    """
    See the description param of router decorator
    """
    return HashcatPerformer().re_run_instance(session_name=str(commons['session_name']))


@router.get(
    '/info',
    description='Get information about a running instance',
    response_model=BruteNTLMInstanceInfoData,
)
def info(commons: dict[str, UUID] = Depends(common_query_session_params)) -> dict[str, str]:
    """
    See the description param of router decorator
    """
    return HashcatPerformer().get_instance_info(session_name=str(commons['session_name']))


@router.get(
    '/info-all',
    description='Get information about all running instances',
    response_model=list[BruteNTLMInstanceInfoData],
)
def info_all() -> list[dict[str, str | list[dict[str, str]]]]:
    """
    See the description param of router decorator
    """
    return HashcatPerformer().get_all_instances_info()
