#!/usr/bin/env python3

from flask import request, session
from flask_restful import Resource, Api

from config import app, db, bcrypt
from models import User

api = Api(app)

class ClearSession(Resource):
    def delete(self):
        session.clear()
        return {}, 204

class Signup(Resource):
    def post(self):
        json = request.get_json()
        user = User(username=json['username'])
        user.set_password(json['password'])
        db.session.add(user)
        db.session.commit()
        return user.to_dict(), 201

class CheckSession(Resource):
    def get(self):
        user_id = session.get('user_id')
        if user_id is not None:
            user = db.session.get(User, user_id)
            return user.to_dict(), 200
        else:
            return {}, 204

class Login(Resource):
    def post(self):
        json = request.get_json()
        username = json.get('username')
        password = json.get('password')

        user = User.query.filter_by(username=username).first()

        if user and user.authenticate(password):
            session['user_id'] = user.id
            return user.to_dict(), 200
        else:
            return {"message": "Invalid credentials"}, 401

class Logout(Resource):
    def delete(self):
        session['user_id'] = None
        return {}, 204


api.add_resource(ClearSession, '/clear', endpoint='clear')
api.add_resource(Signup, '/signup', endpoint='signup')
api.add_resource(CheckSession, '/check_session', endpoint='check_session')
api.add_resource(Login, '/login', endpoint='login')
api.add_resource(Logout, '/logout', endpoint='logout')

if __name__ == '__main__':
    app.run(port=5555, debug=True)
