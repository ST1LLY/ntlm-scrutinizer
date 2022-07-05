"""
Running FastAPI app
"""

import os
import logging
from fastapi import FastAPI

import modules.support_functions as sup_f
from routers import instance, creds, technical

sup_f.init_custome_logger(os.path.join('logs', 'api_all.log'), os.path.join('logs', 'api_error.log'))

# https://stackoverflow.com/a/72238392/14642295
logging.getLogger('uvicorn').removeHandler(logging.getLogger('uvicorn').handlers[0])

app = FastAPI()
app.include_router(instance.router)
app.include_router(creds.router)
app.include_router(technical.router)
