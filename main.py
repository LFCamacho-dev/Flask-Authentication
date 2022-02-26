import os

from flask import Flask, render_template, request, url_for, redirect, flash, send_from_directory
from werkzeug.security import generate_password_hash, check_password_hash
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin, login_user, LoginManager, login_required, current_user, logout_user

app = Flask(__name__)

app.config['SECRET_KEY'] = os.environ.get('FLASK_SECRET')
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)
login_manager = LoginManager()
login_manager.init_app(app)


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


# @login_manager.user_loader
# def load_user(user_id):
#     return User.get(user_id)


# CREATE TABLE IN DB
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(100), unique=True)
    password = db.Column(db.String(100))
    name = db.Column(db.String(1000))

# db.create_all()  # This line only required once, when creating DB.


@app.route('/')
def home():
    return render_template("index.html")


@app.route('/register', methods=["GET", "POST"])
def register():
    error = None
    if request.method == 'POST':
        new_user = User(
            email=request.form.get('email'),
            name=request.form.get('name'),
            password=generate_password_hash(
                request.form.get('password'),
                method='pbkdf2:sha256',
                salt_length=8)
        )
        email_present = User.query.filter_by(email=new_user.email).first()
        if email_present:
            error = "You've already signed up with that email, please login instead."
            return render_template("login.html", error=error)
        else:
            db.session.add(new_user)
            db.session.commit()

            login_user(new_user)

            return redirect(url_for("secrets"))

    return render_template("register.html")


@app.route('/login', methods=["GET", "POST"])
def login():
    error = None
    if request.method == "POST":
        email = request.form.get('email')
        password = request.form.get('password')
        user = User.query.filter_by(email=email).first()
        if not user:
            error = 'That email does not exist, please try again.'
        else:
            if not check_password_hash(user.password, password):
                error = 'Password incorrect, please try again.'
            else:
                login_user(user)
                return redirect(url_for('secrets'))

    return render_template("login.html", error=error)


@app.route('/secrets')
@login_required
def secrets():
    return render_template("secrets.html", name=current_user.name)


@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('home'))


@app.route('/download/')
@login_required
def download():
    return send_from_directory(app.static_folder, path='files/cheat_sheet.pdf')


if __name__ == "__main__":
    app.run(debug=True)
