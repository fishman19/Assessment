from flask import Flask, request, render_template, redirect, url_for, session, abort, flash, jsonify
import uuid, os, hashlib, random, pymysql
app = Flask(__name__)

# Register the setup page and import create_connection()
from utils import create_connection, setup
app.register_blueprint(setup)

@app.before_request
def restrict():
    restricted_pages = ['dashboard', 'view_user', 'edit', 'delete', 'selected', 'add_subject']
    if 'logged_in' not in session and request.endpoint in restricted_pages:
        flash("Sorry, you aren't logged in.")
        return redirect('/login')

@app.route('/')
def home():
    return render_template("index.html")

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

@app.route('/logout')
def logout():
    session.clear()
    return redirect('/')

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

@app.route('/dashboard')
def dashboard():
    if session['role'] != 'admin':
        return abort(404)
    with create_connection() as connection:
        with connection.cursor() as cursor:
            cursor.execute("SELECT * FROM users")
            result = cursor.fetchall()
    return render_template('users_list.html', result=result)

@app.route('/view')
def view_user():
    with create_connection() as connection:
        with connection.cursor() as cursor:
            cursor.execute("SELECT * FROM users WHERE id=%s", request.args['id'])
            result = cursor.fetchone()
    return render_template('users_view.html', result=result)

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

@app.route('/edit', methods=['GET', 'POST'])
def edit():
    if session['role'] != 'admin' and str(session['id']) != request.args['id']:
        flash("Sorry, you don't have permission to edit this user.")
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

@app.route('/subjects')
def subjects():
    with create_connection() as connection:
        with connection.cursor() as cursor:
            cursor.execute("SELECT * FROM subjects")
            result = cursor.fetchall()
    return render_template('subjects.html', result=result)

@app.route('/select')
def select():
    with create_connection() as connection:
        with connection.cursor() as cursor:
            sql = "INSERT INTO selected (student_id, subject_id) VALUES (%s, %s)"
            values = (session['id'], request.args['id'])
            cursor.execute(sql, values)
            connection.commit()
    return redirect('/subjects')

@app.route('/selected')
def selected():
    with create_connection() as connection:
        with connection.cursor() as cursor:
            sql = ("""SELECT users.first_name, users.last_name, subjects.name, subjects.year_level FROM selected
            JOIN users ON selected.student_id = users.id
            JOIN subjects ON subjects.id = selected.subject_id
            WHERE users.id = %s;""")
            values = (session['id'])
            cursor.execute(sql, values)
            result = cursor.fetchall()
    return render_template('selected.html', result=result)

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

@app.route('/delete_selected')
def delete_selected():
    if str(session['id']) != request.args['id']:
        return abort(404)
    with create_connection() as connection:
        with connection.cursor() as cursor:
            sql = "DELETE FROM selected WHERE id = %s"
            values = (request.args['id'])
            cursor.execute(sql, values)
            connection.commit()
    return redirect('/selected')

@app.route('/add_subject')
def add_subject():
    if session['logged_in'] != True or session['role'] != 'admin':
        return abort(404)
    with create_connection() as connection:
            with connection.cursor() as cursor:
                sql = 'INSERT INTO subjects (name, year_level, faculty, HOF) VALUES (%s, %s, %s, %s)'
                values = (request.form['subject'], request.form['year'], request.form['faculty'], request.form['hof'])
                cursor.execute(sql, values)
                result = cursor.fetchone()
            return redirect('subjects')
    return render_template('subjects_add.html')

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
            print(result)
    return render_template('admin_subjects.html', result=result)

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
