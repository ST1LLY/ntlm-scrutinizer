"""
Running FastAPI app
"""

import logging

from fastapi import FastAPI
from routers import instance, creds, technical

logging.getLogger().setLevel(logging.DEBUG)

app = FastAPI()
app.include_router(instance.router)
app.include_router(creds.router)
app.include_router(technical.router)