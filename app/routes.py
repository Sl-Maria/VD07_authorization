from flask import render_template, redirect, url_for, flash, request, flash
from flask_login import login_user, logout_user, current_user, login_required
from app import app, db, bcrypt
from app.models import User
from app.forms import RegistrationForm, LoginForm, AccountForm

@app.route("/")
@app.route("/home")
def home():
    return render_template('home.html')

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
        flash('Регистрация прошла успешно', 'success')
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
            return redirect(url_for('home'))
        else:
            flash('Введён неправильный логин или пароль', 'danger')
    return render_template('login.html', title='Login', form=form)

@app.route("/logout")
def logout():
    logout_user()
    return redirect(url_for('home'))

@app.route("/account", methods=['GET', 'POST'])
@login_required
def account():
    if not current_user.is_authenticated:
        return redirect(url_for('home'))
    form = AccountForm()

    if form.validate_on_submit():
        if form.password.data:
            hashed_password = bcrypt.generate_password_hash(form.password.data).decode('utf-8')
        else:
            hashed_password = current_user.password
        if form.username.data:
            username = form.username.data
        else:
            username = current_user.username
        if form.email.data:
            email = form.email.data
        else:
            email = current_user.email
        user = User(username=username, email=email, password=hashed_password)
        db.session.delete(current_user)
        db.session.commit()
        db.session.add(user)
        db.session.commit()
        flash('Изменения сохранены', 'success')
        logout_user()
        return redirect(url_for('login'))
    else:
        print('form.errors', form.errors)
    return render_template('account.html', title='account', form=form)