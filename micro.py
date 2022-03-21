from flask import Flask, jsonify, request, make_response
from flask_sqlalchemy import SQLAlchemy
import uuid
from werkzeug.security import generate_password_hash, check_password_hash

import jwt
from datetime import datetime, timedelta

app = Flask(__name__)

app.config['SECRET_KEY'] = 'ItIsNotAgoodIdeaToPutYourSecretKEYhere'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:////home/julian/integracion/vens/ejemplo_api/usuarios.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = True

db = SQLAlchemy(app)

class User(db.Model):
    id = db.Column(db.Integer, primary_key = True)
    username = db.Column(db.String(100))
    password = db.Column(db.String(80))
    fs_uniquifier = db.Column(db.String(255), unique=True, nullable=False)


@app.route("/")
def micro():
    return "<p>Hola, microservicio ISI</p>"

@app.route("/api/v1/register", methods=['POST'])
def register():
    if request.headers.get('Content-Type') == 'application/json':
        data = request.get_json()
    user = User(
        username = data["username"],
        password = generate_password_hash(data["password"]),
        fs_uniquifier = str(uuid.uuid4())
    )
    db.session.add(user)
    db.session.commit()
    #print(data["username"])
    #print(data["password"])

    return jsonify({"result":"ok"})

@app.route("/api/v1/login", methods=['GET'])
def login():
    users = User.query.all()
    for user in users:
        if(user.username==request.args["username"] and
            check_password_hash(user.password, request.args["password"])):
            token = jwt.encode({
                'user_id': user.fs_uniquifier,
                'exp': datetime.utcnow() + timedelta(minutes = 60)
            }, app.config['SECRET_KEY'])
            return make_response(jsonify({'token': token.decode('UTF-8')}), 201)

    return make_response(jsonify({"result":"User not found or password incorrect"}), 400)

@app.route("/api/v1/getsecrets", methods=['GET'])
def getsecrets():
    token = None
    if 'x-access-token' in request.headers:
        token = request.headers['x-access-token']
    else:
        return make_response(jsonify({"result":"Something was wrong!"}), 400)
    try:
        data = jwt.decode(token, app.config['SECRET_KEY'])
        current_user = User.query.filter_by(fs_uniquifier = data['user_id']).first()
    except:
        return make_response(jsonify({"result":"Something was wrong with the token!"}), 400)

    return make_response(jsonify({"result":"carpe diem"}), 201)


