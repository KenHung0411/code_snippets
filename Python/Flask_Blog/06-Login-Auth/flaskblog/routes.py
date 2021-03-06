from flask import render_template, url_for, flash, redirect, request,session,jsonify
from flaskblog import app, db, bcrypt, google
from flaskblog.forms import RegistrationForm, LoginForm, UpdateForm
from flaskblog.models import User, Post
from flask_login import login_user, current_user, logout_user, login_required

import requests
import os
import secrets
from PIL import Image

posts = [
    {
        'author': 'Corey Schafer',
        'title': 'Blog Post 1',
        'content': 'First post content',
        'date_posted': 'April 20, 2018'
    },
    {
        'author': 'Jane Doe',
        'title': 'Blog Post 2',
        'content': 'Second post content',
        'date_posted': 'April 21, 2018'
    }
]


@app.route("/")
@app.route("/home")
@login_required
def home():
    return render_template('home.html', posts=posts)


@app.route("/about")
@login_required
def about():
    return render_template('about.html', title='About')


@app.route("/register", methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('home'))
    form = RegistrationForm()
    if form.validate_on_submit():
        hashed_password = bcrypt.generate_password_hash(form.password.data).decode('utf-8')
        user = User(username=form.username.data, email=form.email.data, password=hashed_password)
        db.session.add(user)
        db.session.commit()
        flash('Your account has been created! You are now able to log in', 'success')
        return redirect(url_for('login'))
    return render_template('register.html', title='Register', form=form)


@app.route("/login", methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('home'))
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        if user and bcrypt.check_password_hash(user.password, form.password.data):
            login_user(user, remember=form.remember.data)
            next_page = request.args.get('next')
            return redirect(next_page) if next_page else redirect(url_for('home'))
        else:
            flash('Login Unsuccessful. Please check email and password', 'danger')
    return render_template('login.html', title='Login', form=form)


@app.route("/logout")
def logout():
    logout_user()
    return redirect(url_for('home'))

def save_picture(form_picture):
    random_hex = secrets.token_hex(8)
    _, f_ext = os.path.splitext(form_picture.filename) # underscore _ us to dispose the varible (file name) remain file type
    picture_fn = random_hex + f_ext
    picture_path = os.path.join(app.root_path, 'static/profile_pics', picture_fn)

    output_size = (125, 125)
    i = Image.open(form_picture)
    i.thumbnail(output_size)
    i.save(picture_path)

    return picture_fn

@app.route("/account", methods=['POST','GET'])
@login_required
def account():
    form =  UpdateForm()
    find_user = User.query.filter_by(username = current_user.username).first()

    if form.validate_on_submit():  
    
        find_user.image_file = form.pic_file.data
        if not form.pic_file.data:
            find_user.image_file = 'default.jpg' 

        elif form.pic_file.data:
            picture_file = save_picture(form.pic_file.data)
            find_user.image_file = picture_file

        find_user.username = form.username.data
        find_user.email = form.email.data
        
        db.session.add(find_user)
        db.session.commit()

        return redirect(url_for('home'))

    elif request.method == 'GET':
        form.username.data = current_user.username
        form.email.data = current_user.email

    image_file = url_for('static', filename='profile_pics/' + current_user.image_file)
    return render_template('account.html' , form=form, image_file=image_file)


##Google OAuth 
@app.route('/google-login')
def googleLogin():
    return google.authorize(callback=url_for('authorized', _external=True), prompt='consent')


@app.route('/login/authorized')
@google.authorized_handler
def authorized(resp):
    if resp is None:
        return 'Access denied: reason=%s error=%s' % (
            request.args['error_reason'],
            request.args['error_description']
        )
    session['google_token'] = (resp['access_token'], '')
  
    userinfo = google.get('userinfo')
    me = userinfo.data
    user = User.query.filter_by(email=me['email']).first()
    if not user:
        username = userinfo.data['name']
        email = userinfo.data['email']
        password = userinfo.data['id'] 
        user = User(username=username, email=email, password=password)
        db.session.add(user)
        db.session.commit()

    login_user(user, remember=True)
    flash('login by using google account','info')
    return redirect(url_for('home'))

@google.tokengetter
def get_google_oauth_token():
    return session.get('google_token')

@app.route('/googleOut')
def googleOut():
    session.pop('google_token', None)
    return redirect(url_for('login'))


