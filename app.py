from dotenv import load_dotenv
load_dotenv() 

import os
import boto3
from flask import jsonify
import sqlite3
from flask import Flask, render_template, request, redirect, url_for, session
from werkzeug.security import generate_password_hash, check_password_hash


s3_client = boto3.client('s3',
                         aws_access_key_id=os.getenv('AWS_ACCESS_KEY_ID'),
                         aws_secret_access_key=os.getenv('AWS_SECRET_ACCESS_KEY'),
                         region_name=os.getenv('AWS_REGION'))

app = Flask(__name__)
app.secret_key = '51681ddd65'  # Replace with a secure random string

def create_database():
    conn = sqlite3.connect('alerts.db')
    cursor = conn.cursor()

    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            email TEXT NOT NULL UNIQUE, 
            password TEXT NOT NULL
        )
    ''')

    cursor.execute('''
        CREATE TABLE IF NOT EXISTS alerts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            location TEXT NOT NULL,
            type_of_hazard TEXT NOT NULL,
            warning_level TEXT NOT NULL,
            time TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            photo_video_url TEXT,
            latitude REAL, 
            longitude REAL, 
            FOREIGN KEY(user_id) REFERENCES users(id)
        )
    ''')

    cursor.execute('''
        CREATE TABLE IF NOT EXISTS emergency_contacts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            phone_number TEXT NOT NULL,
            email TEXT 
        )
    ''')

    conn.commit()
    conn.close()

create_database() 

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']

        hashed_password = generate_password_hash(password)

        conn = sqlite3.connect('alerts.db')
        cursor = conn.cursor()
        try:
            cursor.execute('INSERT INTO users (email, password) VALUES (?, ?)', (email, hashed_password))
            conn.commit()
            return redirect(url_for('index')) 
        except sqlite3.IntegrityError:
            return "Email already exists. Please try a different one."
        finally:
            conn.close()

    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']

        conn = sqlite3.connect('alerts.db')
        cursor = conn.cursor()
        cursor.execute('SELECT * FROM users WHERE email = ?', (email,))
        user = cursor.fetchone()
        conn.close()

        if user and check_password_hash(user[2], password):
            session['user_id'] = user[0]
            return redirect(url_for('index'))
        else:
            return "Invalid email or password. Please try again."

    return render_template('login.html')

@app.route('/logout')
def logout():
    session.pop('user_id', None)  # Remove the user_id from the session
    return redirect(url_for('index')) 

@app.route('/add_alert', methods=['GET', 'POST'])
def add_alert():
    if 'user_id' not in session:
        return redirect(url_for('login'))  # Redirect to login if not logged in

    if request.method == 'POST':
        user_id = session['user_id']
        location = request.form['location']
        type_of_hazard = request.form['type_of_hazard']
        warning_level = request.form['warning_level']
        photo_video_url = request.form.get('photo_video_url') 
        latitude = request.form.get('latitude')
        longitude = request.form.get('longitude')

        conn = sqlite3.connect('alerts.db')
        cursor = conn.cursor()
        cursor.execute('''
            INSERT INTO alerts (user_id, location, type_of_hazard, warning_level, photo_video_url, latitude, longitude) 
            VALUES (?, ?, ?, ?, ?, ?, ?)
        ''', (user_id, location, type_of_hazard, warning_level, photo_video_url, latitude, longitude))
        conn.commit()
        conn.close()

        return redirect(url_for('index'))

    return render_template('add_alert.html')

@app.route('/get_alerts')
def get_alerts():
    conn = sqlite3.connect('alerts.db')
    cursor = conn.cursor()
    cursor.execute('SELECT * FROM alerts')
    alerts = cursor.fetchall()
    conn.close()

    # Convert the alert data to a list of dictionaries for JSON serialization
    alerts_data = []
    for alert in alerts:
        alert_dict = {
            'id': alert[0],
            'user_id': alert[1],
            'location': alert[2],
            'type_of_hazard': alert[3],
            'warning_level': alert[4],
            'time': alert[5],
            'photo_video_url': alert[6],
            'latitude': alert[7],
            'longitude': alert[8]
        }
        alerts_data.append(alert_dict)

    return jsonify(alerts_data)

@app.route('/get_upload_url', methods=['POST'])
def get_upload_url():
    if 'user_id' not in session:
        return jsonify({'error': 'Unauthorized'}), 401

    data = request.get_json()
    filename = data['filename']
    bucket_name = 'projetoenchentes' 

    try:
        response = s3_client.generate_presigned_url(
            'put_object',
            Params={'Bucket': bucket_name, 'Key': filename},
            ExpiresIn=3600 
        )
        return jsonify({'url': response})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/delete_alert/<int:alert_id>')
def delete_alert(alert_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))

    # Check if the current user is the admin
    if session.get('user_email') != 'gustavusousa36@gmail.com': 
        return "You are not authorized to delete alerts."

    conn = sqlite3.connect('alerts.db')
    cursor = conn.cursor()
    cursor.execute('DELETE FROM alerts WHERE id = ?', (alert_id,))
    conn.commit()
    conn.close()

    return redirect(url_for('index'))

@app.route('/add_emergency_contact', methods=['GET', 'POST'])
def add_emergency_contact():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    if request.method == 'POST':
        name = request.form['name']
        phone_number = request.form['phone_number']
        email = request.form.get('email')  # Use .get() in case it's empty

        conn = sqlite3.connect('alerts.db')
        cursor = conn.cursor()
        cursor.execute('''
            INSERT INTO emergency_contacts (name, phone_number, email) 
            VALUES (?, ?, ?)
        ''', (name, phone_number, email))
        conn.commit()
        conn.close()

        return redirect(url_for('emergency_info'))  # You'll need to create this route

    return render_template('add_emergency_contact.html')

@app.route('/emergency_info')
def emergency_info():
    conn = sqlite3.connect('alerts.db')
    cursor = conn.cursor()
    cursor.execute('SELECT * FROM emergency_contacts')
    emergency_contacts = cursor.fetchall()
    conn.close()

    return render_template('emergency_info.html', emergency_contacts=emergency_contacts)

@app.route('/')
def index():
    if 'user_id' in session:
        conn = sqlite3.connect('alerts.db')
        cursor = conn.cursor()
        cursor.execute('SELECT email FROM users WHERE id = ?', (session['user_id'],))
        user_email = cursor.fetchone()
        conn.close()
    else:
        user_email = None  # No user logged in

    conn = sqlite3.connect('alerts.db')
    cursor = conn.cursor()

    # Fetch alerts
    cursor.execute('SELECT * FROM alerts')
    alerts = cursor.fetchall()

    # Fetch emergency contacts
    cursor.execute('SELECT * FROM emergency_contacts')
    emergency_contacts = cursor.fetchall()

    conn.close()

    return render_template('index.html', 
                           user_email=user_email, 
                           alerts=alerts, 
                           emergency_contacts=emergency_contacts)

if __name__ == '__main__':
    app.run(debug=True)