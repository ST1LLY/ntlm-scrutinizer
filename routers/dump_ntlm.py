"""
The module contains routers for NTLM dumping logic

Author:
    Konstantin S. (https://github.com/ST1LLY)
"""
import os
import re
from enum import Enum
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field
from starlette.responses import FileResponse

from modules.dump_ntlm_performer import DumpNTLMPerformer   # pylint: disable=import-error
from .common import common_query_session_params

router = APIRouter(
    prefix='/dump-ntlm',
    tags=['dump-ntlm'],
)


class DumpNTLMSessionData(BaseModel):
    """
    Minimal session info
    """

    session_name: str = Field(default=..., title='The session name of running NTLM-hashes dump')


class DumpNTLMParams(BaseModel):
    """
    Params for starting NTLM dump
    """

    target: str = Field(
        default=...,
        title='The format is [[domain/]username[:password]@]<targetName or address>. '
        'Password must be encrypted by aes_256_key from settings.conf',
    )
    just_dc_user: str | None = Field(default=None, title='The specified AD user')


class DumpNTLMInstanceInfoStatus(str, Enum):
    """
    The values of status field in information about dumping session
    """

    FINISHED = 'finished'
    ERROR = 'error'
    RUNNING = 'running'
    INTERRUPTED = 'interrupted'
    NOT_FOUND = 'not_found'


class DumpNTLMInstanceInfoData(BaseModel):
    """
    The information of the NTLM dumping session
    """

    status: DumpNTLMInstanceInfoStatus = Field(default=..., title='The status of the dumping NTLM-hashes process')
    err_desc: str = Field(default=..., title="error description if status = 'error'")
    hashes_file_path: str = Field(default=..., title="path to file with NTLM-hashes if status = 'finished'")


@router.post('/run', description='Dump NTLM-hashes from AD', response_model=DumpNTLMSessionData)
def run(data: DumpNTLMParams) -> dict[str, str]:
    """
    See the description param of router decorator
    """
    return {'session_name': DumpNTLMPerformer().run_instance(data.target, data.just_dc_user)}


@router.get(
    '/status',
    description='Get information about a running process of dumping NTLM-hashes',
    response_model=DumpNTLMInstanceInfoData,
)
def status(commons: dict[str, UUID] = Depends(common_query_session_params)) -> dict[str, str]:
    """
    See the description param of router decorator
    """
    return DumpNTLMPerformer().get_instance_status(str(commons['session_name']))


@router.get('/download-hashes', description='Download file cointains dumped NTLM-hashes')
def download_hashes(file_path: str) -> FileResponse:
    """
    See the description param of router decorator
    """
    if re.match(
        r'/home/user/ntlm-scrutinizer/files/ntlm_hashes/[a-f\d]{8}-?[a-f\d]{4}-?4[a-f\d]{3}-?[89ab][a-f\d]'
        r'{3}-?[a-f\d]{12}\.ntds',
        file_path,
    ) and os.path.exists(file_path):

        return FileResponse(
            path=file_path, filename=os.path.basename(file_path), media_type='application/octet-stream'
        )
    raise HTTPException(status_code=404, detail='File not found')
