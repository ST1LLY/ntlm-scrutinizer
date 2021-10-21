from flask import Blueprint
from flask_restplus import Api

blueprint = Blueprint('api', __name__)

from .namespace_tests import api as ns_tests

api = Api(blueprint, title='API title', description='API description')

api.add_namespace(ns_tests)
