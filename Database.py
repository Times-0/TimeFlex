from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import func
from core import *

MYSQL_USERNAME = 'root'
MYSQL_PASSWORD = ''
MYSQL_DATABASE = 'timeline'

app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql://{}:{}@localhost'.format(MYSQL_USERNAME, MYSQL_PASSWORD)
app.config['SQLALCHEMY_POOL_RECYCLE'] = 3600
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = True

db = SQLAlchemy(app)

class Penguin(db.Model):
    __tablename__ = 'penguins'

    __table_args__ = {
        'autoload': True,
        'schema': MYSQL_DATABASE,
        'autoload_with': db.engine
    }


class Avatar(db.Model):
    __tablename__ = 'avatars'

    __table_args__ = {
        'autoload': True,
        'schema': MYSQL_DATABASE,
        'autoload_with': db.engine
    }


class Membership(db.Model):
    __tablename__ = 'memberships'

    __table_args__ = {
        'autoload': True,
        'schema': MYSQL_DATABASE,
        'autoload_with': db.engine
    }


class Coin(db.Model):
    __tablename__ = 'coins'

    __table_args__ = {
        'autoload': True,
        'schema': MYSQL_DATABASE,
        'autoload_with': db.engine
    }


class Mail(db.Model):
    __tablename__ = 'mails'

    __table_args__ = {
        'autoload': True,
        'schema': MYSQL_DATABASE,
        'autoload_with': db.engine
    }


class Friend(db.Model):
    __tablename__ = 'friends'

    __table_args__ = {
        'autoload': True,
        'schema': MYSQL_DATABASE,
        'autoload_with': db.engine
    }


class Request(db.Model):
    __tablename__ = 'requests'

    __table_args__ = {
        'autoload': True,
        'schema': MYSQL_DATABASE,
        'autoload_with': db.engine
    }


class Ban(db.Model):
    __tablename__ = 'bans'

    __table_args__ = {
        'autoload': True,
        'schema': MYSQL_DATABASE,
        'autoload_with': db.engine
    }


from Session import *
from Firebase import *
from flask import send_file, request, abort, jsonify, Response
from flask_cors import CORS, cross_origin
import traceback

# rate limit to 1 per 5 seconds
@app.route('/flex/nickname/set/<nicknameKey>', methods=['POST'])
@cross_origin(supports_credentials=True)
@limiter.limit('1/5seconds')
def handleSetNickname(nicknameKey):
	if not request.json:
		return jsonify({'error': {'request': 'expected json'}})
	
	data = request.json
	if 'idToken' not in data or 'nickname' not in data:
		return jsonify({'error': {'request.data': 'insufficient data'}})

	tkn = data['idToken']

	try:
		userData = auth.verify_id_token(tkn, check_revoked=True)
		userData = auth.get_user(userData['uid'])

		user = Penguin.query.filter_by(email=userData.email).first()
		if user is None:
			raise Exception("User doesn't exist.")

		swid = user.swid
		key = app.redis.get('nickname_setup_key@{}'.format(swid))

		if key is None or key != nicknameKey or user.nickname != '-_-':
			# possible key expired?
			return jsonify({'error': {'key.expired': 'Key possibly expired. Retry', 'nickname.set': 'failed'}})

		errors = {}
		# check nickname
		data['nickname'] = data['nickname'].strip(' ')
		nickname_w_space = data['nickname'].replace(' ', '')
		if not nickname_w_space.isalnum():
			errors['nickname.syntax'] = 'Nickname can contain only alphabets, numbers and spaces'
		
		if not 3 < len(data['nickname']) < 13:
			errors['nickname.length'] = 'Nickname should be a min of 4 and max of 12 letters (incl spaces)'

		if len(errors) > 0:
			errors['nickname.set'] = 'failed'
			return jsonify({'error': errors})

		user.nickname = data['nickname']
		db.session.commit()

		auth.update_user(userData.uid, display_name=data['nickname'])

		return jsonify({'success': {'nickname.set': True}})

	except Exception, e:
		traceback.print_exc()
		print 'Unable to verify account existance:', e
		return jsonify({'error': {'auth.failed': str(e)}})