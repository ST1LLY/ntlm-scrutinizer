import os
from enum import Enum
from uuid import UUID

from fastapi import APIRouter
from pydantic import BaseModel, Field

import modules.support_functions as sup_f
from enviroment import LOGS_DIR
from .brute_ntlm import HashcatPerformer
from .dump_ntlm import DumpNTLMPerformer

router = APIRouter(
    prefix='/technical',
    tags=['technical'],
)


class BenchmarStatus(str, Enum):
    success = 'success'
    error = 'error'


class BenchmarkData(BaseModel):
    status: BenchmarStatus = Field(default=..., title='The status of benchmark')
    started: str = Field(default=..., title='The datetime of benchmark start')
    stopped: str = Field(default=..., title='The datetime of benchmark stop')
    speeds: list[str] = Field(default=..., title='The speed info of benchmark')

    class Config:
        schema_extra = {
            'example': {
                'status': 'success',
                'started': 'Mon Jul  4 17:07:20 2022',
                'stopped': 'Mon Jul  4 17:07:38 2022',
                'speeds': ['310.1 MH/s (6.40ms) @ Accel:1024 Loops:1024 Thr:1 Vec:8'],
            }
        }


@router.get(
    '/run-benchmark',
    description='Run benchmark for bruting',
    response_model=BenchmarkData,
)
def run_benchmark() -> dict[str, str]:
    return HashcatPerformer().run_benchmark()


@router.get('/clean', description='Clean all data of dumping and bruting')
def clean(session_dump: UUID, session_brute: UUID) -> str:
    for instance in DumpNTLMPerformer.instances:
        if instance['session_name'] == session_dump:
            DumpNTLMPerformer.instances.remove(instance)
            break
    sup_f.delete_if_exists(os.path.join(LOGS_DIR, f'ntlm_dumping_{session_dump}.log'))
    sup_f.delete_if_exists(os.path.join(LOGS_DIR, f'ntlm_dumping_{session_dump}_errors.log'))

    for instance in HashcatPerformer.instances:
        if instance['session_name'] == session_brute:
            HashcatPerformer.instances.remove(instance)
            break

    sup_f.delete_if_exists(os.path.join(LOGS_DIR, f'hashcat_{session_brute}.log'))
    sup_f.delete_if_exists(os.path.join(LOGS_DIR, f'hashcat_{session_brute}_errors.log'))

    return 'success'
