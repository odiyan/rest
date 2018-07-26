from flask import Flask, request, jsonify, make_response
from flask_sqlalchemy import SQLAlchemy
import uuid
from werkzeug.security import generate_password_hash, check_password_hash
import jwt
import datetime
from functools import wraps

app = Flask(__name__)

app.config['SECRET_KEY'] = 'tellnoone' # change in production
app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql+pymysql://username:password@localhost/rest_project'

db = SQLAlchemy(app)

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.String(50), unique=True)
    username = db.Column(db.String(50), unique=True)
    password = db.Column(db.String(80))

def token_required(func):
    @wraps(func)
    def decorated(*args, **kwargs):
        token = None

        if 'x-access-token' in request.headers:
            token = request.headers['x-access-token']

        if not token:
            return jsonify({'message': 'Token is missing!'}), 401

        try:
            data = jwt.decode(token, app.config['SECRET_KEY'])
            current_user = User.query.filter_by(user_id=data['user_id']).first()

        except:
            return jsonify({'message': 'Token is invalid!'}), 401

        return func(current_user, *args, **kwargs)

    return decorated

@app.route('/users', methods=['GET'])
@token_required
def get_all_users(current_user):
    # retrieves data of all users

    # get all users from db
    users = User.query.all()
    output = []

    #populate from db into a variable and return json
    for user in users:
        user_data = {}
        user_data['username'] = user.username
        user_data['id'] = user.id
        user_data['password'] = user.password
        user_data['user_id'] = user.user_id
        output.append(user_data)

    return jsonify({'users': output})

@app.route('/user', methods=['POST'])
def create_user():
    # creates new user from json request
    # username and password parameters to be supplied

    #retrieve data from json request
    data = request.get_json()

    hashed_password = generate_password_hash(data['password'], method='sha256')
    new_user = User(username=data['username'], password=hashed_password, user_id=str(uuid.uuid4()))
    db.session.add(new_user)
    db.session.commit()

    return jsonify({'message': 'New user created'})

@app.route('/login')
def login():
    # setup HTTP basic authentication
    
    auth = request.authorization

    if not auth or not auth.username or not auth.password:
        return make_response('Could not verify', 401, {'WWW-Authenticate': 'Basic realm="Login required!"'})

    user = User.query.filter_by(username=auth.username).first()

    if not user:
        return make_response('User not found', 401, {'WWW-Authenticate': 'Basic realm="Login required!"'})

    if check_password_hash(user.password, auth.password):
        token = jwt.encode({'user_id': user.user_id, 'exp': datetime.datetime.utcnow() + datetime.timedelta(minutes=30)}, \
                           app.config['SECRET_KEY'])

        return jsonify({'token': token.decode('UTF-8')})

    return make_response('Could not verify', 401, {'WWW-Authenticate': 'Basic realm="Login required!"'})
    

if __name__ == '__main__':
    import logging
    logging.basicConfig(filename='error.log',level=logging.DEBUG)
    app.run(debug=True)
