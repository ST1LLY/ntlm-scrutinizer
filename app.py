"""
Running Flask app
"""

import logging
import datetime
from flask import Flask
from apis import blueprint as api

logging.getLogger().setLevel(logging.DEBUG)

app = Flask(__name__)
app.logger.setLevel(logging.DEBUG)
app.secret_key = b'9WvmP6JFnYzAEFnsj2vxXJDEFGHXUhjg'
app.permanent_session_lifetime = datetime.timedelta(minutes=60)
app.register_blueprint(api, url_prefix='/api')
app.logger.handlers.clear()
