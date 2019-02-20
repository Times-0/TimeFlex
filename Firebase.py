import firebase_admin
from firebase_admin import auth
from firebase_admin import credentials
from core import *
from flask_cors import cross_origin

cred = credentials.Certificate("./config/FirebaseCredential.json")
FIREBASE_APP = firebase_admin.initialize_app(cred)

from Session import *
from Database import *
from flask import send_file, request, abort, jsonify, Response
from json import dumps
import traceback


@app.route('/flex/user/<swid>/detail', methods=['POST'])
@cross_origin(supports_credentials=True)
def getUserDetail(swid):
	userData = {}

	user = Penguin.query.filter_by(swid=swid).first()
	if not user:
		return abort(404)

	# avatar = Avatar.query.filter_by(penguin_id=user.id).first()
	member = Membership.query.filter_by(penguin_id=user.id).order_by(Membership.expires.desc()).first()
	coins = Coin.query.with_entities(func.sum(Coin.transaction)).filter_by(penguin_id=user.id).scalar() or 0
	mail_count = Mail.query.filter_by(penguin_id=user.id, opened=0).count() or 0

	if session['login_data']['swid'] != swid:
		userData['user.name'] = user.nickname
		online = app.redis.hgetall("online:{}".format(user.id))
		userData['user.online'] = online['place_name'] if online and 'place_name' in online and not user.moderator else None
		if user.moderator:
			userData['user.moderator'] = True

		_friend = Friend.query.filter_by(penguin_id=user.id, friend=session['login_data']['swid']).first()
		userData['user.friend'] = False if _friend is None else True
		if  _friend is not None:
			userData['friend.since'] = str(_friend.befriended)
			userData['friend.bff'] = bool(int(_friend.bff))

		return jsonify(userData)

	userData['member.data'] = {'expire':  str(member.expires), 'since': str(member.redeemed_on or None)} if member else {}
	userData['coins.count'] = int(coins)
	userData['mail.count'] = int(mail_count)
	
	if user.moderator:
		userData['moderator.data'] = {}
		if user.moderator == 1:
			userData['moderator.data']['meta'] = 'Moderator'
		elif user.moderator == 2:
			userData['moderator.data']['meta'] = 'Stealth Mod'
		elif user.moderator == 3:
			userData['moderator.data']['meta'] = 'Mascot'

	return jsonify(userData)


@app.route('/flex/user/<swid>/coins', methods=['POST'])
@cross_origin(supports_credentials=True)
def getUserCoinHistory(swid):
	try:
		if swid != session['login_data']['swid']:
			return abort(404)

		user = Penguin.query.filter_by(swid=swid).first()
		if not user:
			return abort(404)

		coins = Coin.query.filter_by(penguin_id=user.id).order_by(Coin.id.desc()).limit(100).all()
		userData = {}
		userData['coins.data'] = {coin.id : {'transaction': coin.transaction, 'comment': coin.comment} for coin in coins}

		return jsonify(userData)
	except:
		traceback.print_exc()


@app.route('/flex/user/<swid>/bans', methods=['POST'])
@cross_origin(supports_credentials=True)
def getUserBanHistory(swid):
	try:
		if swid != session['login_data']['swid']:
			return abort(404)

		user = Penguin.query.filter_by(swid=swid).first()
		if not user:
			return abort(404)

		bans = Ban.query.filter_by(penguin_id=user.id).order_by(Ban.id.desc()).all()
		userData = {}
		userData['bans.data'] = {ban.id : {'moderator': ban.moderator, 'comment': ban.comment, 'expire': str(ban.expire), 'since': str(ban.time)} for ban in bans}

		return jsonify(userData)
	except:
		traceback.print_exc()


@app.route('/flex/user/<swid>/friends', methods=['POST'])
@cross_origin(supports_credentials=True)
def getUserFriendsDetail(swid):

	user = Penguin.query.filter_by(swid=swid).first()
	if not user:
		return abort(404)

	userData = {}
	friends = Friend.query.filter_by(penguin_id=user.id)
	requests = Request.query.filter_by(penguin_id=user.id)

	userData['friend.count'] = int(friends.count())
	userData['request.count'] = int(requests.count())

	if swid == session['login_data']['swid']:
		userData['friend.data'] = {str(friend.friend) : {'since': str(friend.befriended), 'bff': bool(int(friend.bff))} for friend in friends.all()}
		userData['request.data'] = [str(r.requested_by) for i in requests.all()]

	return jsonify(userData)


@app.route('/flex/user/signout', methods=['POST', 'GET'])
@cross_origin(supports_credentials=True)
def signOut():
	if 'login_data' in session:
		session.pop('login_data')

	return jsonify({'user.signout': 'login_data' not in session})