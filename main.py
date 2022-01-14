from flask import Flask , jsonify, request , Response
from flask_sqlalchemy import SQLAlchemy
app = Flask(__name__)

app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///data.db'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///User.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = True
UPLOAD_FOLDER = 'C:/uploads'
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['MAX_CONTENT_LENGTH'] = 5 * 1024 * 1024
app.config['SECRET_KEY'] = 'secret_key'

db = SQLAlchemy(app)
database = SQLAlchemy(app)

class User(database.Model):
	id = database.Column(database.Integer, primary_key = True)
	public_id = database.Column(database.String(50), unique = True)
	name = database.Column(database.String(100))
	email = database.Column(database.String(70), unique = True)
	password = database.Column(database.String(80))

class Person(db.Model):

    __tablename__ = 'Demographic Details'  # creating a table name
    id = db.Column(db.Integer, primary_key=True)  
    Name = db.Column(db.String(80), nullable=False)
    Age = db.Column(db.Integer, nullable=False)
    City = db.Column(db.String(80), nullable=False)
   
    def json(self):
        return {'id': self.id, 'Name': self.Name,
                'Age': self.Age, 'City': self.City}


    def add_person(_Name, _Age, _City):
        new_person = Person(Name=_Name, Age = _Age, City=_City)
        db.session.add(new_person)  
        db.session.commit()  

    def get_all_persons():
        '''function to get all persons in our database'''
        return [Person.json(person) for person in Person.query.all()]

    def get_person(_id):
        '''function to get person using the id of the person as parameter'''
        return [Person.json(Person.query.filter_by(id=_id).first())]
    

    def update_person(_id, _Name, _Age, _City):
        '''function to update the details of a person using the id, name,
        age and city as parameters'''
        Person_to_update = Person.query.filter_by(id=_id).first()
        Person_to_update.Name = _Name
        Person_to_update.Age = _Age
        Person_to_update.City = _City
        db.session.commit()

    def delete_person(_id):
        '''function to delete a movie from our database using
           the id of the person as a parameter'''
        Person.query.filter_by(id=_id).delete()
        db.session.commit()  
