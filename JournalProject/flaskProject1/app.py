from flask import Flask, render_template, request, redirect, url_for, abort, flash
import flask_login
from flask_sqlalchemy import SQLAlchemy
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
import wtforms_alchemy as alchemy

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///{}/{}'.format(app.root_path, 'final.db')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SECRET_KEY'] = 'b2de7FkqvkMyqzNFzxCkgnPKIGP6i4Rc'

db = SQLAlchemy(app)

login_manager = flask_login.LoginManager()
login_manager.init_app(app)


class User(flask_login.UserMixin, db.Model):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(255), nullable=False, unique=True)
    username = db.Column(db.String(50), nullable=False, unique=True)
    password = db.Column(db.String(255), nullable=False)
    characters = db.relationship('Character', backref='User', lazy=True)


@login_manager.user_loader
def user_loader(id):
    return User.get(id)


class Character(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(50), nullable=False)
    ancestry = db.Column(db.String(50), nullable=False)
    archetype = db.Column(db.String(50), nullable=False)
    game_system = db.Column(db.String(50), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey(User.id))
    entries = db.relationship('Entry', backref='Character', lazy=True)


class Entry(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(50), nullable=False)
    desc = db.Column(db.Text(50000), nullable=False)
    character_id = db.Column(db.Integer, db.ForeignKey(Character.id))


class LoginForm(FlaskForm):
    username = StringField('Username')
    password = PasswordField('Password')
    submit = SubmitField('Submit')


class CharacterForm(alchemy.ModelForm):
    class Meta:
        model = Character


class EntryForm(alchemy.ModelForm):
    class Meta:
        model = Entry


db.create_all()


@app.route('/login', methods=['GET', 'POST'])
def login():

    form = LoginForm()
    if form.validate_on_submit():

        flask_login.login_user(user)

        return redirect(url_for('index'))
    return render_template('login.html', form=form)


@app.route('/logout')
def logout():
    flask_login.logout_user()
    return 'Logged out'


@app.route('/')
def index():
    return render_template('index.html')


@app.route('/home')
@flask_login.login_required
def home():
    return render_template('home.html')



if __name__ == '__main__':
    app.run()
