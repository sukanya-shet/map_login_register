from flask import Flask, render_template, redirect, url_for
from Forms import LoginForm,RegisterForm
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import LoginManager,UserMixin,login_user, login_required, logout_user, current_user
import os
app = Flask(__name__)

BASE_DIR = os.path.abspath(os.path.dirname(__file__))
app.config['SECRET_KEY'] = "secret"
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"]= False
app.config["SQLALCHEMY_DATABASE_URI"] = 'sqlite:///' + os.path.join(BASE_DIR, 'data.sqlite')

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view='login'
db=SQLAlchemy(app)

class User(UserMixin,db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String, unique=True)
    password = db.Column(db.String)

db.create_all()

@app.route('/')
def home():
    return render_template('base.html')


@app.route('/register',methods=['GET','POST'])
def register():
    form = RegisterForm()
    if form.is_submitted():
        crtypted_password = generate_password_hash(form.password.data, method='sha256')
        new_user = User(username=form.username.data, password=crtypted_password)
        db.session.add(new_user)
        db.session.commit()
        return redirect(url_for('login'))
    return render_template('register.html',form=form)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))
@app.route('/login',methods=['GET','POST'])
def login():
    form = LoginForm()
    if form.is_submitted():
        user = User.query.filter_by(username=form.username.data).first()
        if user:
            if check_password_hash(user.password,form.password.data):
                login_user(user)
                return "Login successful!"
            else:
                return "Incorrect password!"
        else:
            return "Invalid username or password!"
    return render_template('login.html',form=form)


@app.route('/map')
@login_required
def map():
    return render_template('map.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('index'))


if __name__ == "__main__":
    app.run(debug=True)
