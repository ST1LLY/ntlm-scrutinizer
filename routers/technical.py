from enum import Enum

from fastapi import APIRouter
from pydantic import BaseModel, Field

from modules.hashcat_performer import HashcatPerformer

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
