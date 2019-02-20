from flask import Flask
from flask_caching import Cache
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

app = Flask('TimeFlex')
cache = Cache(app, config={'CACHE_TYPE': 'redis'})
limiter = Limiter(
    app,
    key_func=get_remote_address,
    default_limits=["5/second"]
)