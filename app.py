from flask import Flask, render_template, redirect, url_for,request, flash, session
from flask_bcrypt import Bcrypt
from flask_sqlalchemy import SQLAlchemy
from datetime import datetime
import logging

app = Flask(__name__)

app.config.from_pyfile('config.cfg')
bcrypt = Bcrypt(app)
db = SQLAlchemy(app)

class Users(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    fullName = db.Column(db.String(30), unique=True, nullable=False)
    phone = db.Column(db.Integer, unique=True, default=0)
    email = db.Column(db.String(50), unique=True, nullable=False)
    password = db.Column(db.String(30), unique=True, nullable=False)
    admin = db.Column(db.Boolean, default=False)

    news = db.relationship('News', backref='author', lazy='dynamic')

    def __repr__(self):
        return '<User %r>' % self.fullName

class News(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    headline = db.Column(db.String(150), unique=True, nullable=False)
    description = db.Column(db.Text, nullable=False)
    category = db.Column(db.String(30), nullable=False)
    uploaded_at = db.Column(db.DateTime, default=datetime.now())
    author_id = db.Column(db.Integer, db.ForeignKey('users.id'))


@app.route('/')
def index():
    if 'loggedin' in session:
        userId = session['userId']
        user = Users.query.filter(Users.id==userId).first()
        return render_template('index.html',
                                user=user,
                                date=datetime.now())

    return render_template('index.html', 
    date=datetime.now())

@app.route('/news')
def news():
    newsdb = News.query.order_by(News.uploaded_at.desc()).all()

    if 'loggedin' in session:
        userId = session['userId']
        user = Users.query.filter(Users.id == userId).first()
        return render_template('news.html', user=user, newsdb=newsdb)

    return render_template('news.html', newsdb=newsdb)

@app.route('/addNews', methods=['GET','POST'])
def addNews():
    if 'loggedin' in session:
        userId = session['userId']
        user = Users.query.get_or_404(userId)
        if request.method == 'POST' and 'headline' in request.form and 'description' in request.form and 'category' in request.form:
            headline = request.form['headline']
            description = request.form['description']
            category = request.form['category']

            news1 = News(headline=headline, description=description, category=category, author_id=userId)
            db.session.add(news1)
            db.session.commit()
            flash('News added successfully!', category='info')
            app.logger.info('%s added news' % user.fullName)
            return redirect(url_for('news'))
    else:
        flash('Please Sign-in for adding news!', category='warning')
        return redirect(url_for('signin'))

    return redirect(url_for('index'))

@app.route('/deleteNews/<int:id>')
def deleteNews(id):
    userId = session['userId']
    news = News.query.get_or_404(id)
    user = Users.query.get_or_404(userId)
    if 'loggedin' in session:
        if news.author_id == userId or user.admin:
            # news = News.query.get_or_404(id)
            db.session.delete(news)
            db.session.commit()
            app.logger.info('%s deleted news' % user.fullName)
            flash('News deletion successful!', category='info')
            return redirect(url_for('news'))
        else:
            flash('Permission denied!', category='warning')
            return redirect(url_for('news'))   
    else:
        flash('Please Sign-in for deleting news!', category='warning')
        return redirect(url_for('signin'))

    return redirect(url_for('index'))
    

@app.route('/editNews/<int:id>', methods=['GET','POST'])
def editNews(id):
    userId = session['userId']
    news = News.query.get_or_404(id)
    user = Users.query.get_or_404(userId)

    if 'loggedin' in session:
        #matching user to his news/post 
        if news.author_id == userId or user.admin:

            if request.method == 'POST' and 'headline' in request.form and 'description' in request.form and 'category' in request.form:
                news.headline = request.form['headline']
                news.description = request.form['description']
                news.category = request.form['category']
                db.session.commit()
                app.logger.info('%s edited news' % user.fullName)
                return redirect(url_for('news'))
        else:
            flash('Permission denied!', category='warning')
            return redirect(url_for('news'))

    return render_template('editNews.html', news=news)

@app.route('/contact')
def contact():
    if 'loggedin' in session:
        userId = session['userId']
        user = Users.query.filter(Users.id == userId).first()
        return render_template('contact.html', user=user)

    return render_template('contact.html')

@app.route('/signin', methods=['GET', 'POST'])
def signin():
    if 'loggedin' in session:
        return redirect(url_for('index'))
    # Check if "username" and "password" POST requests exist (user submitted form)
    if request.method == 'POST' and 'email' in request.form and 'password' in request.form:
        # Create variables for easy access
        email = request.form['email']
        password = request.form['password']
        # Check if account exists using MySQL
        user = Users.query.filter(Users.email==email).first()
        # hashpass = bcrypt.generate_password_hash(password).decode('utf-8')
        # print(hashpass)
        # If account exists in accounts table in out database
        if user:
            passwd = bcrypt.check_password_hash(user.password, password)
            if passwd:
                # Create session data, we can access this data in other routes
                session['loggedin'] = True
                session['userId'] = user.id
                session['admin'] = user.admin
                # Redirect to home page
                app.logger.info('%s signed in' % user.fullName)
                return redirect(url_for('index'))
            else:
                flash('Incorrect password!', category='error')
        else:
            # Account doesnt exist or username/password incorrect
            flash('user not found!', category='error')

    return render_template('signin.html')

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if 'loggedin' in session:
        return redirect(url_for('index'))
    # Check if POST requests exist (user submitted form)
    if request.method == 'POST' and 'fullName' in request.form and 'email' in request.form and 'password' in request.form:
        # Create variables for easy access
        fullName = request.form['fullName']
        phone = request.form['phone']
        email = request.form['email']
        password = bcrypt.generate_password_hash(request.form['password']).decode('utf-8')
        
        # Check if account exists using MySQL
        account = Users.query.filter(db.or_(Users.fullName==fullName, Users.email==email)).first()
        # If account exists show error and validation checks
        if account:
            flash('Account already exists! ', category='error')
        elif not fullName or not password or not email:
            flash('Please fill out the form!', category='error')
        else:
            # Account doesnt exists and the form data is valid, now insert new account into accounts table
            user = Users(fullName=fullName, phone=phone, email=email, password=password)
            db.session.add(user)
            db.session.commit()
            session['loggedin'] = True
            session['userId'] = user.id
            session['admin'] = user.admin
            app.logger.info('%s signed up and logged in' % user.fullName)
            flash('Registered successfully!', category='info')
            return redirect(url_for('index'))
            
    elif request.method == 'POST':
        # Form is empty... (no POST data)
        flash('Please fill out the form!', category='error')
    # Show signup form with message (if any)
    return render_template('signup.html')

@app.route('/profile')
def profile():
    # Check if user is loggedin
    if 'loggedin' in session:
        # We need all the account info for the user so we can display it on the profile page
        userId = session['userId']
        user = Users.query.filter(Users.id==userId).first()
        # Show the profile page with account info
        return render_template('profile.html', user=user)
    # User is not loggedin redirect to login page
    return redirect(url_for('index'))

@app.route('/logout')
def logout():
    # Remove session data, this will log the user out
    session.pop('loggedin', None)
    session.pop('userId', None)
    # Redirect to login page
    app.logger.info('user logged out')
    return redirect(url_for('index'))

@app.route('/editProfile/<int:id>', methods=['GET','POST'])
def editProfile(id):
    user = Users.query.get_or_404(id)
    if 'loggedin' in session:
        if user.id == session['userId'] or session['admin']:
            if request.method == 'POST' and 'fullName' in request.form and 'email' in request.form:
                fullName = request.form['fullName']
                phone = request.form['phone']
                email = request.form['email']
                # updating data
                editUser(user, fullName, phone, email)
                app.logger.info('%s updated profile' % user.fullName)
                flash('Profile updated successfully!', category='info')
                return redirect(url_for('profile'))
        else:
            flash('Permission Denied!', category='warning')
            return redirect(url_for('profile'))
    else:
        flash('Please Sign-in first!', category='warning')
        return redirect(url_for('signin'))

@app.route('/deleteProfile/<int:id>')
def deleteProfile(id):
    user = Users.query.get_or_404(id)

    if 'loggedin' in session:
        if user.id == session['userId'] or session['admin']:
            deleteUser(user)
            app.logger.info('%s deleted profile' % user.fullName)
            if session['admin']:
                return redirect(url_for('ViewUsers'))
            else:
                logout()
                return redirect(url_for('index'))
        else:
            flash('Permission Denied!', category='warning')
            return redirect(url_for('profile'))
    else:
        flash('Please Sign-in first!', category='warning')
        return redirect(url_for('signin'))

@app.route('/resetPassword/<int:id>', methods=['GET','POST'])
def resetPassword(id):
    user = Users.query.get_or_404(id)
    if 'loggedin' in session:
        if user.id == session['userId'] or session['admin']:
            if request.method == 'POST' and 'password' in request.form and 'cnfmPassword' in request.form:
                password = request.form['password']
                cnfmPassword = request.form['cnfmPassword']

                if password != cnfmPassword:
                    flash('Passwords do not match! Try again...', category='error')
                    return redirect(url_for('profile'))
                else:
                    resetUserPass(user, password)
                    app.logger.info('%s changed password' % user.fullName)
                    flash('Success! Please Sign-in with new password...', category='info')
                    logout()
                    return redirect(url_for('signin'))
        else:
            flash('Permission Denied!', category='warning')
            return redirect(url_for('profile'))
    else:
        flash('Please Sign-in first!', category='warning')
        return redirect(url_for('signin'))

# Defining profile handling Functions
def editUser(user, fullName, phone, email):
    # updating data
    user.fullName = fullName
    user.phone = phone
    user.email = email
    db.session.commit()

def deleteUser(user):
    db.session.delete(user)
    db.session.commit()

def resetUserPass(user, password):
    pass_hash = bcrypt.generate_password_hash(password).decode('utf-8')
    user.password = pass_hash
    db.session.commit()

@app.route('/viewUsers')
def viewUsers():
    if 'loggedin' in session:
        userId = session['userId']
        user = Users.query.get_or_404(userId)
        all_users = Users.query.all()

        return render_template('viewUser.html', all_users = all_users, user=user)
    else:
        flash('Please Sign-in first!', category='warning')
        return redirect(url_for('signin'))

# @app.route('/manageUser/<int:id>', methods=['GET', 'POST'])
# def manageUser(id):
#     user = Users.query.get_or_404(id)
#     if 'loggedin' in session and session['admin']:

#         if request.method == 'POST' and 'fullName' in request.form and 'email' in request.form:
#             fullName = request.form['fullName']
#             phone = request.form['phone']
#             email = request.form['email']
#             editUser(user, fullName, phone, email)
#             return redirect(url_for('viewUsers'))

#         elif request.method == 'POST' and 'password' in request.form and 'cnfmPassword' in request.form:
#             password = request.form['password']
#             cnfmPassword = request.form['cnfmPassword']

#             if password != cnfmPassword:
#                 flash('Passwords do not match! Try again...', category='error')
#                 return redirect(url_for('viewUsers'))            
#             else:
#                 resetUserPass(user, password)
#                 return redirect(url_for('viewUsers'))

#         elif request.method == 'POST' and 'delete' in request.form:
#             deleteUser(user)
#             return redirect(url_for('viewUsers'))

#     else:
#         flash('Permission Denied!', category='warning')
#         return redirect(url_for('index'))

if __name__== '__main__':
    app.secret_key = 'twhkehberuoraddgcfadsvtw'

    # Setting up a log file for user action
    handler = logging.FileHandler('user.log')
    handler.setLevel(logging.INFO)
    # Formatting data into log file
    formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
    handler.setFormatter(formatter)
    # Adding handler to app logger
    app.logger.addHandler(handler)
    app.run(debug=True)