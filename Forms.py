from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, BooleanField,SubmitField
from wtforms.validators import InputRequired, Length

class LoginForm(FlaskForm):
    username = StringField('Username',validators=[InputRequired(),Length(min=4)])
    password = PasswordField('Password', validators=[InputRequired(), Length(min=4)])
    submit = SubmitField("Login")
    remember = BooleanField('Remember me')

class RegisterForm(FlaskForm):
    username = StringField('Username',validators=[InputRequired(),Length(min=4)])
    password = PasswordField('Password',validators=[InputRequired(),Length(min=4)])
    submit = SubmitField("Register")