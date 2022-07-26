"""
Running FastAPI app
"""

import logging
import os

from fastapi import FastAPI

import modules.support_functions as sup_f
from enviroment import LOGS_DIR
from routers import dump_ntlm, brute_ntlm, creds, technical

sup_f.init_custome_logger(os.path.join(LOGS_DIR, 'api_all.log'), os.path.join(LOGS_DIR, 'api_error.log'))


if logging.getLogger('uvicorn').handlers:
    # https://stackoverflow.com/a/72238392/14642295
    logging.getLogger('uvicorn').removeHandler(logging.getLogger('uvicorn').handlers[0])

app = FastAPI()
app.include_router(dump_ntlm.router)
app.include_router(brute_ntlm.router)
app.include_router(creds.router)
app.include_router(technical.router)
