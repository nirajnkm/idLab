from flask import Flask, request, render_template, redirect, session
from flask_pymongo import PyMongo
import bcrypt
from dotenv import load_dotenv
load_dotenv()
import os

app = Flask(__name__)
app.config['MONGO_URI'] = os.getenv('MONGO_URI')
app.secret_key = os.getenv('SECRET_KEY')

mongo = PyMongo(app)

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        name = request.form.get('name')
        email = request.form.get('email')
        password = request.form.get('password')
        if not name or not email or not password:
            return render_template('register.html', error='Please fill in all the fields')
        role = request.form.get('role', 'user')

        existing_user = mongo.db.users.find_one({'email': email})

        if existing_user:
            return render_template('register.html', error='User already exists')

        hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
        new_user = {
            'name': name,
            'email': email,
            'password': hashed_password,
            'role': role
        }

        mongo.db.users.insert_one(new_user)
        return redirect('/login')

    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']

        user = mongo.db.users.find_one({'email': email})

        if user and bcrypt.checkpw(password.encode('utf-8'), user['password'].encode('utf-8')):
            session['email'] = user['email']
            if user['role'] == 'admin':
                return redirect('/admindashboard')
            else:
                return redirect('/dashboard')
        else:
            return render_template('login.html', error='Invalid user')

    return render_template('login.html')

@app.route('/admindashboard')
def admindashboard():
    if 'email' in session:
        user = mongo.db.users.find_one({'email': session['email']})
        return render_template('admindashboard.html', user=user)

    return redirect('/login')

@app.route('/dashboard')
def dashboard():
    if 'email' in session:
        user = mongo.db.users.find_one({'email': session['email']})
        return render_template('dashboard.html', user=user)

    return redirect('/login')

@app.route('/logout')
def logout():
    session.pop('email', None)
    return redirect('/login')

if __name__ == '__main__':
    app.run(debug=True)
