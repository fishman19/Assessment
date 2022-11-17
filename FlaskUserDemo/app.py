from flask import Flask, request, render_template, redirect, url_for, session, abort, flash, jsonify
import uuid, os, hashlib, random, pymysql
from datetime import date, datetime
app = Flask(__name__)

# Register the setup page and import create_connection()
from utils import create_connection, setup
app.register_blueprint(setup)

# Redirects user to login page if trying to access restricted page when not logged in
@app.before_request
def restrict():
    restricted_pages = ['dashboard', 'view_user', 'edit', 'delete', 'selected', 'add_subject', 'delete_selected', 'select']
    if 'logged_in' not in session and request.endpoint in restricted_pages:
        flash("Sorry, you aren't logged in.")
        return redirect('/login')

# Home page of the site
@app.route('/')
def home():
    return render_template("index.html")

# Allows the user to login to their account with username and password
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        password = request.form['password']
        encrypted_password = hashlib.sha256(password.encode()).hexdigest()
        with create_connection() as connection:
            with connection.cursor() as cursor:
                sql = "SELECT * FROM users WHERE email=%s AND password=%s"
                values = (request.form['email'], encrypted_password)
                cursor.execute(sql, values)
                result = cursor.fetchone()
        if result:
            session['logged_in'] = True
            session['first_name'] = result['first_name']
            session['role'] = result['role']
            session['id'] = result['id']
            if session['role'] == 'admin':
                return redirect('/dashboard')
            else:
                return redirect('/')
        else:
            flash('Sorry! Your username or password information was wrong. Please try again or sign up if you do not have an account.')
            return redirect("/login")
    else:
        return render_template('login.html')

# Logs the user out of their account
@app.route('/logout')
def logout():
    session.clear()
    return redirect('/')

# Allows the user to enter their information to create an account
@app.route('/register', methods=['GET', 'POST'])
def add_user():
    if request.method == 'POST':
        password = request.form['password']
        encrypted_password = hashlib.sha256(password.encode()).hexdigest()
        if request.files['avatar'].filename:
            avatar_image = request.files["avatar"]
            ext = os.path.splitext(avatar_image.filename)[1]
            avatar_filename = str(uuid.uuid4())[:8] + ext
            avatar_image.save("static/images/" + avatar_filename)
        else:
            avatar_filename = None
        with create_connection() as connection:
            with connection.cursor() as cursor:
                sql = 'INSERT INTO users (first_name, last_name, core_class, email, password, avatar) VALUES (%s, %s, %s, %s, %s, %s)'
                values = (request.form['first_name'], request.form['last_name'], request.form['class'], request.form['email'], encrypted_password, avatar_filename)
                try:
                    cursor.execute(sql, values)
                    connection.commit()
                except pymysql.err.IntegrityError:
                    flash('Email has already been taken')
                    return redirect('/register')
                sql = "SELECT * FROM users WHERE email=%s AND password=%s"
                values = (request.form['email'], encrypted_password)
                cursor.execute(sql, values)
                result = cursor.fetchone()
        if result:
            session['logged_in'] = True
            session['first_name'] = result['first_name']
            session['role'] = result['role']
            session['id'] = result['id']
        return redirect('/')
    return render_template('users_add.html')

# List of all users accessible only to admin users
@app.route('/dashboard')
def dashboard():
    if session['role'] != 'admin':
        return abort(404)
    with create_connection() as connection:
        with connection.cursor() as cursor:
            cursor.execute("SELECT * FROM users")
            result = cursor.fetchall()
    return render_template('users_list.html', result=result)

# Allows a user to view their profile
@app.route('/view')
def view_user():
    with create_connection() as connection:
        with connection.cursor() as cursor:
            cursor.execute("SELECT * FROM users WHERE id=%s", request.args['id'])
            result = cursor.fetchone()
    return render_template('users_view.html', result=result)

# Deletes a user's account
@app.route('/delete')
def delete():
    if session['role'] != 'admin' and str(session['id']) != request.args['id']:
        return abort(404)
    with create_connection() as connection:
        with connection.cursor() as cursor:
            sql = "DELETE FROM users WHERE id = %s"
            values = (request.args['id'])
            cursor.execute(sql, values)
            connection.commit()
    if str(session['id']) == request.args['id']:
        session.clear()
        return redirect('/')
    else:
        return redirect('/dashboard')

# Allows a user to edit their account information
@app.route('/edit', methods=['GET', 'POST'])
def edit():
    if session['role'] != 'admin' and str(session['id']) != request.args['id']:
        return redirect('/view?id=' + request.args['id'])
    if request.method == 'POST':
        if request.files['avatar'].filename:
            avatar_image = request.files["avatar"]
            ext = os.path.splitext(avatar_image.filename)[1]
            avatar_filename = str(uuid.uuid4())[:8] + ext
            avatar_image.save("static/images/" + avatar_filename)
            if request.form['old_avatar'] != 'None':
                os.remove("static/images/" + request.form['old_avatar'])
        elif request.form['old_avatar'] != 'None':
            avatar_filename = request.form['old_avatar']
        else:
            avatar_filename = None

        with create_connection() as connection:
            with connection.cursor() as cursor:
                if request.form['password']:
                    password = request.form['password']
                    encrypted_password = hashlib.sha256(password.encode()).hexdigest()
                    sql = "UPDATE users SET first_name = %s, last_name = %s, core_class = %s, email = %s, password = %s, avatar = %s WHERE id = %s"
                    values = (request.form['first_name'], request.form['last_name'], request.form['core_class'], request.form['email'], encrypted_password, avatar_filename, request.form['id'])
                else:
                    sql = "UPDATE users SET first_name = %s, last_name = %s, core_class = %s, email = %s, avatar = %s WHERE id = %s"
                    values = (request.form['first_name'], request.form['last_name'], request.form['core_class'], request.form['email'], avatar_filename, request.form['id'])
                cursor.execute(sql, values)
                connection.commit()
        if session['role'] == 'admin':
            return redirect(url_for('dashboard'))
        else:
            return redirect(url_for('home'))
    else:
        with create_connection() as connection:
            with connection.cursor() as cursor:
                sql = "SELECT * FROM users WHERE id = %s"
                values = (request.args['id'])
                cursor.execute(sql, values)
                result = cursor.fetchone()
        return render_template('users_edit.html', result=result)

# Checks if a new user's email is already taken or not
@app.route('/check_email')
def check_email():
    with create_connection() as connection:
        with connection.cursor() as cursor:
            sql = "SELECT * FROM users WHERE email=%s"
            values = (request.args['email'])
            cursor.execute(sql, values)
            result = cursor.fetchone()
        if result:
            return jsonify({ 'status': 'Taken' })
        else:
            return jsonify({ 'status': 'OK' })

# List of subjects available for selection
@app.route('/subjects')
def subjects():
    with create_connection() as connection:
        with connection.cursor() as cursor:
            cursor.execute("SELECT * FROM subjects")
            result = cursor.fetchall()
    return render_template('subjects.html', result=result)

# Selects a subject and adds it to a student's selected list
@app.route('/select')
def select():
    if session['role'] == 'admin':
        return abort(404)
    datenow = datetime.now()
    duedate = datetime(2023,7,12, 11,59,59)
    startdate = datetime(2022,7,6)
    if datenow > duedate or datenow < startdate:
        flash('The subject selection period has ended. If you need to add a subject, please notify your teacher.')
        return redirect('/subjects')
    else:
        with create_connection() as connection:
            with connection.cursor() as cursor:
                sql = """SELECT users.first_name, subjects.name FROM selected
                         JOIN users ON selected.student_id = users.id
                         JOIN subjects ON selected.subject_id = subjects.id
                         WHERE users.id = %s"""
                values = (session['id'])
                cursor.execute(sql, values)
                result = cursor.fetchall()
                if len(result) < 5:
                    sql = """INSERT INTO selected (student_id, subject_id) VALUES (%s, %s)"""
                    values = (session['id'], request.args['id'])
                    try:
                        cursor.execute(sql, values)
                        connection.commit()
                    except pymysql.err.IntegrityError:
                        flash('You have already chosen this subject.')
                        return redirect('/subjects')
                else:
                    flash('You already have 5 subjects. Edit your profile to remove a subject first.')
                    return redirect('/subjects')
        return redirect('/subjects')

# List of subjects that a student has selected
@app.route('/selected')
def selected():
    with create_connection() as connection:
        with connection.cursor() as cursor:
            sql = ("""SELECT users.first_name, users.last_name, subjects.name, subjects.year_level, subjects.id FROM selected
            JOIN users ON selected.student_id = users.id
            JOIN subjects ON subjects.id = selected.subject_id
            WHERE users.id = %s;""")
            values = (session['id'])
            cursor.execute(sql, values)
            result = cursor.fetchall()
    return render_template('selected.html', result=result)

# Deletes a subject from the list of available subjects
@app.route('/delete_subject')
def delete_subject():
    if session['role'] != 'admin':
        return abort(404)
    with create_connection() as connection:
        with connection.cursor() as cursor:
            sql = "DELETE FROM subjects WHERE id = %s"
            values = (request.args['id'])
            cursor.execute(sql, values)
            connection.commit()
    return redirect('/subjects')

# Removes a subject from a student's list of selected subjects
@app.route('/delete_selected')
def delete_selected():
    if session['logged_in'] != True:
        return abort(404)
    with create_connection() as connection:
        with connection.cursor() as cursor:
            sql = "DELETE FROM selected WHERE student_id = %s AND subject_id = %s"
            values = (session['id'], request.args['id'])
            cursor.execute(sql, values)
            connection.commit()
    return redirect('/selected')

# Allows an admin user to add new subjects to the subject list
@app.route('/add_subject', methods=['GET', 'POST'])
def add_subject():
    if session['logged_in'] != True or session['role'] != 'admin':
        return abort(404)
    if request.method == 'POST':
        with create_connection() as connection:
                with connection.cursor() as cursor:
                    sql = 'INSERT INTO subjects (name, year_level, faculty, teacher_in_charge) VALUES (%s, %s, %s, %s)'
                    values = (request.form['subject'], request.form['year'], request.form['faculty'], request.form['teacher'])
                    cursor.execute(sql, values)
                    result = cursor.fetchone()
                    connection.commit()
        return redirect('/subjects')
    return render_template('subjects_add.html')

# List of all students and their selected subjects (admin only)
@app.route('/admin_subjects')
def admin_subjects():
    if session['logged_in'] != True or session['role'] != 'admin':
        return abort(404)
    with create_connection() as connection:
        with connection.cursor() as cursor:
            cursor.execute("""SELECT users.id, users.first_name, users.last_name, GROUP_CONCAT(subjects.name) FROM selected
            JOIN users ON selected.student_id = users.id
            JOIN subjects ON subjects.id = selected.subject_id
            GROUP BY users.id;""")
            result = cursor.fetchall()
            connection.commit()
    return render_template('admin_selected.html', result=result)
 
# View list of students who have selected a particular subject
@app.route('/view_subject')
def subjects_view():
    if session['role'] != 'admin':
        return abort(404)
    with create_connection() as connection:
        with connection.cursor() as cursor:
            sql = ("""SELECT * FROM selected
            JOIN users ON selected.student_id = users.id
            JOIN subjects ON subjects.id = selected.subject_id
            WHERE subjects.id = %s""")
            values = (request.args['id'])
            cursor.execute(sql, values)
            result = cursor.fetchall()
            connection.commit()
            print(result)
    return render_template('subjects_view.html', result=result)

# Edit information about subjects
@app.route('/edit_subject', methods=['GET', 'POST'])
def subjects_edit():
    if session['role'] != 'admin':
        return abort(404)
    if request.method == 'POST':
        with create_connection() as connection:
            with connection.cursor() as cursor:
                sql = "UPDATE subjects SET name = %s, year_level = %s, faculty = %s, teacher_in_charge = %s WHERE id = %s"
                values = (request.form['subject'], request.form['year_level'], request.form['faculty'], request.form['teacher'], request.form['id'])
                cursor.execute(sql, values)
                connection.commit()
        if session['role'] == 'admin':
            return redirect(url_for('subjects'))
    else:
        with create_connection() as connection:
            with connection.cursor() as cursor:
                sql = "SELECT * FROM subjects WHERE id = %s"
                values = (request.args['id'])
                cursor.execute(sql, values)
                result = cursor.fetchone()
        return render_template('subjects_edit.html', result=result)

if __name__ == '__main__':
    import os

    # This is required to allow flashing messages. We will cover this later.
    app.secret_key = os.urandom(32)

    HOST = os.environ.get('SERVER_HOST', 'localhost')
    try:
        PORT = int(os.environ.get('SERVER_PORT', '5555'))
    except ValueError:
        PORT = 5555
    app.run(HOST, PORT, debug=True)
