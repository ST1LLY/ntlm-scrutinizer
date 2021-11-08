"""
Initiating external API
"""
from flask import Blueprint
from flask_restplus import Api

blueprint = Blueprint('api', __name__)

from .namespace_ntlm_scr import api as ns_ntlm_scr

api = Api(blueprint, title='NTLM scrutinizer', description='https://github.com/ST1LLY/ntlm-scrutinizer')

api.add_namespace(ns_ntlm_scr)
