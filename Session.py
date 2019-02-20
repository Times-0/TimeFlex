from flask import Flask, session
from flask_session import Session
from core import *

app.config['SESSION_TYPE'] = 'redis'
app.secret_key = 'dd3d50bd-2c48-4c77-b668-49c11d0026af'

Session(app)