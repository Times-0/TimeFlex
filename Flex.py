'''
Timeflex : Web server for Timeline's v2 user management system
Developer: Dote
Version: 2.0
Login: Firebase authentication
'''

from Session import *
from Database import *
from Firebase import *

from flask import send_file, request, abort, jsonify, Response
from flask_cors import CORS, cross_origin
from flask_session import Session

from core import *
from time import time
from os import urandom
from redis import Redis

import traceback
from hashlib import md5
import bcrypt, datetime

redis = Redis()

app.redis = redis
app.config['CORS_HEADERS'] = 'Content-Type'
CORS(app, supports_credentials=True, origins=['play.localhost', 'localhost'])

BCRYPT_SALT = "$2b$12$xxcjQIy5KifXvMdfSdq25O"
AVATAR_URL = "//localhost:5050/{swid}/cp"

# rate limit to 5 per 2 seconds
@app.route('/flex/login/username', methods=['POST'])
@cross_origin(supports_credentials=True)
@limiter.limit('5/2seconds')
def loginUsingUsername():
	if not request.json:
		return jsonify({'error': {'request': 'expected json'}})
	
	data = request.json
	if 'username' not in data or 'password' not in data:
		return jsonify({'error': {'request.data': 'login data insufficient'}})

	username = str(data['username']).decode('base64')
	password = str(data['password']).decode('base64')

	user = Penguin.query.filter_by(username=username).first()
	if user is None:
		return jsonify({'error': {'login.user': 'user not found'}})

	if user.password == 'firebase':
		# firebase account exists, return linking email, only if password is correct
		dbpasswd = user.hash
		if not bcrypt.hashpw(password, BCRYPT_SALT) == dbpasswd:
			return jsonify({'error': {'login.user': 'incorrect credentials'}})

		return jsonify({'login.email': user.email})

	# check password, then create a user in firebase db, then upgrade password to bcrypt
	if md5(password).hexdigest() != user.password:
		return jsonify({'error': {'login.user': 'incorrect credentials'}})

	try:
		user_ = auth.get_user_by_email(user.email)
		if user_.custom_claims['swid'] != user.swid:
			return jsonify({'error': {'login.integration': 'Email already linked with another account'}})
		else:
			raise Exception("All fine, proceed")
	except auth.AuthError:
		# user doesn't exist, create
		u = auth.create_user(display_name=user.nickname, email=user.email, email_verified=True, password=password)
		user.hash = bcrypt.hashpw(password, BCRYPT_SALT)
		user.password = "firebase"
		db.session.commit()

	return jsonify({'login.email': user.email})


# rate limi to 5 per 2 second
@app.route('/flex/login/status', methods=['POST'])
@cross_origin(supports_credentials=True)
@limiter.limit('5/2seconds')
def getLoginStatus():
	if not request.json:
		return jsonify({'error': {'request': 'expected json'}})
	
	data = request.json
	if not 'idToken' in data:
		return jsonify({'error': {'request.data': 'no login data found'}})

	tkn = data['idToken']
	try:
		userData_ = auth.verify_id_token(tkn, check_revoked=True)
		if 'login_data' in session and (userData_['uid'] != session['login_data']['uid'] or userData_['swid'] != session['login_data']['swid']):
			session.pop('login_data')
	except:
		traceback.print_exc()
		return abort(404)


	data = {'login.status': 'login_data' in session}
	if data['login.status']:
		data['login.data'] = session['login_data']['swid']

	return jsonify(data)

# rate limit to 5 per 2 seconds
@app.route('/flex/login/', methods=['POST'])
@cross_origin(supports_credentials=True)
@limiter.limit('5/2seconds')
def loginUsingIdToken():
	if not request.json:
		return jsonify({'error': {'request': 'expected json'}})
	
	data = request.json
	if not 'idToken' in data:
		return jsonify({'error': {'request.data': 'no login data found'}})

	tkn = data['idToken']

	'''
	Check idToken, confirm user log in : auth.verify_id_token(tkn, check_revoked=True)
	Set login_data, send login status to user
	'''

	try:
		userData_ = auth.verify_id_token(tkn, check_revoked=True)

		if 'login_data' in session:
			try:
				if session['login_data']['uid'] == userData_['uid']:
					# user already logged in, trying to change signature ig?
					session['login_data']['signature'] = tkn
					redis.set('Auth-{}'.format(session['login_data']['swid']), tkn, ex=int(userData_['exp']-time()))

					return jsonify({'success': {'login.data': session['login_data']['swid'], 'login.status': 2}}) # 2 => login refresh (session)

				else:
					# trying to switch session, reset the current one
					session['login_data'] = None
			except:
				session['login_data'] = None

		'''
		Check for user profile
		- Check if a user already exists in Penguins table with given email
			- if not exists, create one. Ask user for displayName (nickname), membership and color
			- if exists, set displayName to nickname

		- set custom claims (swid) if not exists
		- integrate firebase user id with local db user

		* don't integrate unless user verified their email-address

		Note: user cannot merge firebase with local account of different email address
		'''
		userData = auth.get_user(userData_['uid'])
		try:
			user = Penguin.query.filter_by(email=userData.email).first() # find user by email
			if user is None:
				# not exist, create one
				uname = 'P-{}'.format(urandom(5).encode('hex'))
				user = Penguin(username=uname, password='firebase', email=userData.email, nickname='-_-') # -_- -> to set nickname yet
				db.session.add(user)
				db.session.commit()

				db.session.add(Avatar(penguin_id=user.id, language=0))
				db.session.add(Coin(penguin_id=user.id, transaction=500, comment="New user bonus"))
				db.session.add(Membership(penguin_id=user.id, expires='{} 00:00:00'.format((datetime.date.today() + datetime.timedelta(7)).isoformat()), redeemed_on='{} 00:00:00'.format(datetime.date.today().isoformat()), comments="Redeemed 7-day auto free trial membership. - Timeline Server"))

				db.session.commit()

			avatar = Avatar.query.filter_by(penguin_id=user.id).first()
		except:
			traceback.print_exc()
			return jsonify({'error': {'auth.failed': 'database error', 'database.error': 'error verifying user'}})

		# check if email is verified, don't continue otherwise
		if not userData.email_verified:
			avatar.language = 0
			return jsonify({'error': {'email.verify': 'Profile locked. Verify email to continue', 'login.status': 'disabled'}})

		if avatar.language == 0 and userData.email_verified:
			avatar.language = 45 # default
			db.session.commit()

		errors = {}
		# once user verified email and proved themself to be owner of the account, integrate accounts if not done before.

		if user.nickname == '-_-':
			# ask user to set nickname
			nicknameSetupKey = redis.get('nickname_setup_key@{}'.format(user.swid))
			setKey = nicknameSetupKey == None
			nicknameSetupKey = urandom(10).encode('hex') if nicknameSetupKey is None else nicknameSetupKey
			redis.set('nickname_setup_key@{}'.format(user.swid), nicknameSetupKey, ex=15*60) if setKey else None # only for 15 minutes

			session['nickname_setup_key'] = nicknameSetupKey
			errors['profile.incomplete'] = 'Set nickname to continue login'
			errors['nickname.setup'] = nicknameSetupKey
			errors['login.status'] = 'blocked'
		else:
			# check for account integration, ie user-claims [swid]
			swid = userData.custom_claims.get('swid') if userData.custom_claims is not None else None
			if swid is not None and swid != user.swid:
				print 'Account linked to another account. Overriding. You can change this feature in line 209'
				swid = None # comment this whole line to disable account link overriding
			
			if swid is None:
				# integrate accounts
				userData = auth.update_user(userData.uid, custom_claims={'swid': user.swid}, photo_url=AVATAR_URL.format(swid=user.swid))
				swid = userData.custom_claims.get('swid')

		if userData.display_name != user.nickname:
			userData = auth.update_user(userData.uid, display_name=user.nickname)

		if len(errors) > 0:
			errors['auth.failed'] = 'Profile integrity check failed' if 'auth.failed' not in errors else errors['auth.failed']
			return jsonify({'error': errors})

		print 'Logged in'
		# user successfully logged in
		session['login_data'] = {
			'signature': tkn, # to get (raw) user data, use auth.verify_id_token
			'uid': userData.uid,
			'swid': user.swid
		}
		session.modified = True

		redis.set('Auth-{}'.format(session['login_data']['swid']), tkn, ex=int(userData_['exp']-time())) # use this to login to game, refresh when expires

		return jsonify({'success': {'login.data': session['login_data']['swid'], 'login.status': 1}}) # 1 => fresh login (session)

	except Exception, e:
		traceback.print_exc()
		print 'Unable to verify account existance:', e
		return jsonify({'error': {'auth.failed': str(e)}})


@app.before_request
def check_valid_login():
	requiresAuth = request.path.startswith('/flex/user')

	if requiresAuth:
		if not 'login_data' in session or not request.json or 'signature' not in request.json:
			return abort(403)

		try:
			user = auth.verify_id_token(request.json['signature'])
			if user['uid'] != session['login_data']['uid']:
				return abort(403)

		except:
			traceback.print_exc()
			return abort(403)


@app.errorhandler(403)
@cross_origin(supports_credentials=True)
def page_unauthorized(e):
	return jsonify({'error': {403: 'access denied', 'login': 'requires login'}})


@app.errorhandler(404)
@cross_origin(supports_credentials=True)
def page_not_found(e):
	return jsonify({'error': {404:'emptiness detected'}})


@app.errorhandler(501)
@app.errorhandler(500)
@cross_origin(supports_credentials=True)
def page_rip(e):
	return jsonify({'error': {'panic': 'hawking radiation detected', 501: 'black holes'}})


@app.errorhandler(429)
@cross_origin(supports_credentials=True)
def page_rip(e):
	return jsonify({'error': {'chill': 'chill and have breeze for a second', 429: 'rate limited'}})


@app.errorhandler(405)
@cross_origin(supports_credentials=True)
def page_restricted(e):
	return jsonify({'error': {'stop': 'just stop', 405: 'nope'}})


@app.errorhandler(400)
@cross_origin(supports_credentials=True)
def page_oopsie(e):
	return jsonify({'error': {'oops': 'oopsie. big oopsie.', 400: 'yeah, oopsie'}})

app.run(host='', port=2086, debug=False, threaded=True)