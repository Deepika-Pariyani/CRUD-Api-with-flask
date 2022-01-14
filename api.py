from main import *
from flask import Flask, request, jsonify, make_response, redirect
from flask_sqlalchemy import SQLAlchemy
import uuid 
from werkzeug.security import generate_password_hash, check_password_hash
import jwt
from datetime import datetime, timedelta
from functools import wraps
import os
import urllib.request
from werkzeug.utils import secure_filename

def token_required(f):
	@wraps(f)
	def decorated(*args, **kwargs):
		token = None
		# jwt is passed in the request header
		if 'x-access-token' in request.headers:
			token = request.headers['x-access-token']
		# return 401 if token is not passed
		if not token:
			return jsonify({'message' : 'Token is missing !!'}), 401

		try:
			# decoding the payload to fetch the stored details
			data = jwt.decode(token, app.config['SECRET_KEY'])
			current_user = User.query.filter_by(public_id = data['public_id']).first()
		except:
			return jsonify({
				'message' : 'Token is invalid !!'
			}), 401
		# returns the current logged in users contex to the routes
		return f(current_user, *args, **kwargs)
	return decorated

@app.route('/login', methods =['POST'])
def login():
	# creates dictionary of form data
	auth = request.form

	if not auth or not auth.get('email') or not auth.get('password'):
		# returns 401 if any email or / and password is missing
		return make_response(
			'Could not verify',
			401,
			{'WWW-Authenticate' : 'Basic realm ="Login required !!"'}
		)
	user = User.query\
		.filter_by(email = auth.get('email'))\
		.first()

	if not user:
		# returns 401 if user does not exist
		return make_response(
			'Could not verify',
			401,
			{'WWW-Authenticate' : 'Basic realm ="User does not exist !!"'}
		)

	if check_password_hash(user.password, auth.get('password')):
		# generates the JWT Token
		token = jwt.encode({
			'public_id': user.public_id,
			'exp' : datetime.utcnow() + timedelta(minutes = 30)
		}, app.config['SECRET_KEY'])
        
		return make_response(jsonify({'token' : token.decode('utf-8')}), 201)
	# returns 403 if password is wrong
	return make_response(
		'Could not verify',
		403,
		{'WWW-Authenticate' : 'Basic realm ="Wrong Password !!"'}
	)

	
@app.route('/user', methods =['GET'])
@token_required
def get_all_users(current_user):
    # querying the database
    # for all the entries in it
    users = User.query.all()
    # converting the query objects
    # to list of jsons
    output = []
    for user in users:
        # appending the user data json
        # to the response list
        output.append({
            'public_id': user.public_id,
            'name' : user.name,
            'email' : user.email
        })
  
    return jsonify({'users': output})

	
# signup route
@app.route('/signup', methods =['POST'])
def signup():
	# creates a dictionary of the form data
	data = request.form

	# gets name, email and password
	name, email = data.get('name'), data.get('email')
	password = data.get('password')

	# checking for existing user
	user = User.query\
		.filter_by(email = email)\
		.first()
	if not user:
		# database ORM object
		user = User(
			public_id = str(uuid.uuid4()),
			name = name,
			email = email,
			password = generate_password_hash(password)
		)
		# insert user
		db.session.add(user)
		db.session.commit()

		return make_response('Successfully registered.', 201)
	else:
		# returns 202 if user already exists
		return make_response('User already exists. Please Log in.', 202)


@app.route('/person', methods=['GET'])
def get_person():
    '''Function to get all the persons in the database'''
    return jsonify({'Persons': Person.get_all_persons()})

# route to get person by id
@app.route('/person/<int:id>', methods=['GET'])
def get_person_by_id(id):
    return_value = Person.get_person(id)
    return jsonify(return_value)

# route to add new person
@app.route('/person', methods=['POST'])
def add_person():
    '''Function to add new person to our database'''
    request_data = request.get_json()  # getting data from client
    Person.add_person(request_data["Name"], request_data["Age"], request_data["City"])
    response = Response("person added", 201, mimetype='application/json')
    data = {
        "Name" : request_data["Name"],
        "Age" : request_data["Age"],
        "City" : request_data["City"]
    }
    return  data

# route to update person with PUT method
@app.route('/person/<int:id>', methods=['PUT'])
def update_person(id):
    '''Function to edit person in our database using id'''
    request_data = request.get_json()
    Person.update_person(id, request_data['Name'], request_data['Age'], request_data['City'])
    response = Response("Person data Updated", status=200, mimetype='application/json')
    return response

# route to delete person using the DELETE method
@app.route('/person/<int:id>', methods=['DELETE'])
def remove_person(id):
    '''Function to delete person from our database'''
    Person.delete_person(id)
    response = Response("Person data Deleted", status=200, mimetype='application/json')
    return response


#uploading files
ALLOWED_EXTENSIONS = set(['txt', 'pdf', 'png', 'jpg', 'jpeg', 'gif'])

def allowed_file(filename):
	return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

@app.route('/upload', methods=['POST'])
def upload_file():
	# check if the post request has the file part
	if 'file' not in request.files:
		resp = jsonify({'message' : 'No file part in the request'})
		resp.status_code = 400
		return resp
	file = request.files['file']
	if file.filename == '':
		resp = jsonify({'message' : 'No file selected for uploading'})
		resp.status_code = 400
		return resp
	if file and allowed_file(file.filename):
		try:
			filename = secure_filename(file.filename)
			file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
			resp = jsonify({'message' : 'File successfully uploaded'})
			resp.status_code = 201
		except:
			directory = "uploads"
			parent_dir = "C:/uploads"
			path = os.path.join(parent_dir, directory)
			filename = secure_filename(file.filename)
			file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
			resp = jsonify({'message' : 'File successfully uploaded'})
			resp.status_code = 201

		return resp
	else:
		resp = jsonify({'message' : 'Allowed file types are txt, pdf, png, jpg, jpeg, gif'})
		resp.status_code = 400
		return resp

if __name__ == "__main__":
    app.run(debug=True)