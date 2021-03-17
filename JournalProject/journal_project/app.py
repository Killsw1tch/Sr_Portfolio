from flask import Flask, render_template, redirect, url_for, g, request
from flask_bootstrap import Bootstrap
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, BooleanField, IntegerField
from wtforms.widgets import HiddenInput
from wtforms.validators import InputRequired, Email, Length
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///{}/{}'.format(app.root_path, 'final.db')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SECRET_KEY'] = 'b2de7FkqvkMyqzNFzxCkgnPKIGP6i4Rc'
Bootstrap(app)
db = SQLAlchemy(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'


class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(20))
    email = db.Column(db.String(30), unique=True)
    password = db.Column(db.String(80))
    characters = db.relationship('Character', backref='user', lazy=True)


class Character(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(50), nullable=False)
    ancestry = db.Column(db.String(50), nullable=False)
    archetype = db.Column(db.String(50), nullable=False)
    system = db.Column(db.String(50), nullable=False)
    entries = db.relationship('Entry', backref='character', lazy=True)
    user_id = db.Column(db.Integer, db.ForeignKey(User.id))


class Entry(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(50), nullable=False)
    entry = db.Column(db.Text(50000), nullable=False)
    character_id = db.Column(db.Integer, db.ForeignKey(Character.id))


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


class LoginForm(FlaskForm):
    username = StringField('username', validators=[InputRequired(), Length(min=4, max=20)])
    password = PasswordField('password', validators=[InputRequired(), Length(min=5, max=80)])
    remember = BooleanField('remember me')


class RegisterForm(FlaskForm):
    email = StringField('email', validators=[InputRequired(), Email(message="Invalid Email"), Length(min=6, max=30)])
    username = StringField('username', validators=[InputRequired(), Length(min=4, max=20)])
    password = PasswordField('password', validators=[InputRequired(), Length(min=5, max=80)])


db.create_all()


@app.route('/')
def index():
    return render_template('index.html')


@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()

    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user:
            # compares the password hash in the db and the hash of the password typed in the form
            if check_password_hash(user.password, form.password.data):
                login_user(user, remember=form.remember.data)
                return redirect(url_for('dashboard'))
        return 'invalid username or password'

    return render_template('login.html', form=form)


@app.route('/signup', methods=['GET', 'POST'])
def signup():
    form = RegisterForm()

    if form.validate_on_submit():
        hashed_password = generate_password_hash(form.password.data, method='sha256')
        # add the user form input which is form.'field'.data into the column which is 'field'
        new_user = User(username=form.username.data, email=form.email.data, password=hashed_password)
        db.session.add(new_user)
        db.session.commit()
        return redirect(url_for('login'))

    return render_template('signup.html', form=form)


@app.route('/dashboard')
@login_required
def dashboard():
    g.user = current_user.get_id()
    characters = Character.query.filter(Character.user_id == g.user)
    return render_template('dashboard.html', name=current_user.username, characters=characters)


@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('index'))


@app.route('/character/<id>')
@login_required
def character(id):
    entity = Character.query.filter(Character.id == id and Character.user_id == User.id).first()
    entries = Entry.query.filter(Entry.character_id == Character.id and Character.user_id == User.id)
    return render_template('character.html', entity=entity, entries=entries)


@app.route('/characterForm', methods=("GET", "POST"))
@login_required
def create_character():

    if request.method == 'POST':
        name = request.form['name']
        ancestry = request.form['ancestry']
        archetype = request.form['archetype']
        system = request.form['system']
        user_id = request.form['user_id']

        error = None

        if not request.form['name']:
            error = 'Name is required'

        if error is None:
            person = Character(name=name, ancestry=ancestry, archetype=archetype, system=system, user_id=user_id)
            db.session.add(person)
            db.session.commit()
            return redirect(url_for('dashboard'))
    characters = Character.query.all()
    return render_template('character-form.html', characters=characters)


@app.route('/delete_character/<id>')
@login_required
def delete_character(id):
    entity = Character.query.get_or_404(id)
    db.session.delete(entity)
    db.session.commit()
    return redirect(url_for('dashboard'))


@app.route('/entryForm/<character_id>', methods=("GET", "POST"))
@login_required
def create_entry(character_id):
    character = Character.query.get_or_404(character_id)
    if request.method == 'POST':
        title = request.form['title']
        entry = request.form['entry']
        character_id = request.form['character_id']

        error = None

        if not request.form['entry']:
            error = 'Entry is required'

        if error is None:
            page = Entry(title=title, entry=entry, character_id=character_id)
            db.session.add(page)
            db.session.commit()
            return redirect(url_for('dashboard'))
    entries = Entry.query.all()
    return render_template('/entry-form.html', entries=entries, character=character)


@app.route('/delete_entry/<id>')
@login_required
def delete_entry(id):
    entry = Entry.query.get_or_404(id)
    db.session.delete(entry)
    db.session.commit()
    return redirect(url_for('dashboard'))


if __name__ == '__main__':
    app.run()
