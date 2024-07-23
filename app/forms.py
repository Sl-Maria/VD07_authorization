from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField, BooleanField
from wtforms.validators import DataRequired, Length, Email, EqualTo, ValidationError, Optional

from app.models import User

class RegistrationForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired(), Length(min=2, max=20)])
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired()])
    confirm_password = PasswordField('Confirm Password', validators=[DataRequired(), EqualTo('password')])
    submit = SubmitField('Sign Up')

    def validate_username(self, username):
        user = User.query.filter_by(username=username.data).first()
        if user:
            raise ValidationError('Tакое имя пользователя уже существует. Пожалуйста, выберите другое.')

    def validate_email(self, email):
        user = User.query.filter_by(email=email.data).first()
        if user:
            raise ValidationError('Такая почта уже используется. Пожалуйста, выберите другую.')

class LoginForm(FlaskForm):
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired()])
    remember = BooleanField('Remember Me')
    submit = SubmitField('Login')

class AccountForm(FlaskForm):
    username = StringField('Username', validators=[Optional(), Length(min=2, max=20)])
    email = StringField('Email', validators=[Optional(), Email()])
    password = PasswordField('New Password', validators=[EqualTo('confirm_password')])
    confirm_password = PasswordField('Confirm New Password', validators=[EqualTo('password')])
    submit = SubmitField('Сохранить изменения')

    def validate_username(self, username):
        user = User.query.filter_by(username=username.data).first()
        if user:
            raise ValidationError('Tакое имя пользователя уже существует. Пожалуйста, выберите другое.')

    def validate_email(self, email):
        user = User.query.filter_by(email=email.data).first()
        if user:
            raise ValidationError('Такая почта уже используется. Пожалуйста, выберите другую.')