# session_utils.py

from flask import session

def createUserSession(userId, userName, email, roles, idToken):
    session['user'] = {
        'id': userId,
        'username': userName,
        'email': email,
        'roles': roles,
        'id_token': idToken
    }

def clearUserSession():
    session.pop('user', None)
    session.pop('token', None)

def getUserFromSession():
    return session.get('user')
