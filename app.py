from flask import Flask, render_template, request
from flask import redirect, url_for, jsonify, make_response

import jwt
import datetime
import os

from functools import wraps

from werkzeug.security import (
    generate_password_hash,
    check_password_hash
)

from flask_sqlalchemy import SQLAlchemy

# -----------------------------------
# FLASK APP
# -----------------------------------
app = Flask(__name__)

# -----------------------------------
# CONFIG
# -----------------------------------
SECRET_KEY = os.environ.get(
    "SECRET_KEY",
    "dev_secret_key"
)

app.config["SECRET_KEY"] = SECRET_KEY

app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///users.db"

app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

db = SQLAlchemy(app)

# -----------------------------------
# DATABASE MODEL
# -----------------------------------
class User(db.Model):

    id = db.Column(
        db.Integer,
        primary_key=True
    )

    username = db.Column(
        db.String(80),
        unique=True,
        nullable=False
    )

    password = db.Column(
        db.String(200),
        nullable=False
    )

# -----------------------------------
# CREATE DATABASE
# -----------------------------------
with app.app_context():

    db.create_all()

    user1 = User.query.filter_by(
        username="aaaa"
    ).first()

    if not user1:

        db.session.add(
            User(
                username="aaaa",
                password=generate_password_hash("1234")
            )
        )

    user2 = User.query.filter_by(
        username="krishna"
    ).first()

    if not user2:

        db.session.add(
            User(
                username="krishna",
                password=generate_password_hash("password")
            )
        )

    db.session.commit()

# -----------------------------------
# CREATE TOKEN
# -----------------------------------
def create_token(username):

    payload = {

        "username": username,

        "exp":
        datetime.datetime.utcnow()
        + datetime.timedelta(minutes=30)

    }

    token = jwt.encode(
        payload,
        SECRET_KEY,
        algorithm="HS256"
    )

    return token

# -----------------------------------
# TOKEN REQUIRED
# -----------------------------------
def token_required(f):

    @wraps(f)
    def decorated(*args, **kwargs):

        token = request.cookies.get(
            "jwt_token"
        )

        if not token:

            return redirect(
                url_for("login")
            )

        try:

            data = jwt.decode(
                token,
                SECRET_KEY,
                algorithms=["HS256"]
            )

            current_user = User.query.filter_by(
                username=data["username"]
            ).first()

            if not current_user:

                return redirect(
                    url_for("login")
                )

        except jwt.ExpiredSignatureError:

            return redirect(
                url_for("login")
            )

        except jwt.InvalidTokenError:

            return redirect(
                url_for("login")
            )

        return f(
            current_user,
            *args,
            **kwargs
        )

    return decorated

# -----------------------------------
# HOME
# -----------------------------------
@app.route("/")
def home():

    return redirect(
        url_for("login")
    )

# -----------------------------------
# LOGIN PAGE
# -----------------------------------
@app.route("/login")
def login():

    return render_template(
        "login.html"
    )

# -----------------------------------
# LOGIN POST
# -----------------------------------
@app.route(
    "/login",
    methods=["POST"]
)
def login_post():

    username = request.form.get(
        "username"
    )

    password = request.form.get(
        "password"
    )

    user = User.query.filter_by(
        username=username
    ).first()

    if user and check_password_hash(
        user.password,
        password
    ):

        token = create_token(
            username
        )

        response = make_response(
            redirect(
                url_for("dashboard")
            )
        )

        response.set_cookie(
            "jwt_token",
            token,
            httponly=True,
            secure=False,
            samesite="Lax",
            max_age=1800
        )

        return response

    return render_template(
        "login.html",
        error="Invalid credentials"
    )

# -----------------------------------
# REGISTER PAGE
# -----------------------------------
@app.route("/register")
def register():

    return render_template(
        "register.html"
    )

# -----------------------------------
# REGISTER POST
# -----------------------------------
@app.route(
    "/register",
    methods=["POST"]
)
def register_post():

    username = request.form.get(
        "username"
    )

    password = request.form.get(
        "password"
    )

    existing_user = User.query.filter_by(
        username=username
    ).first()

    if existing_user:

        return render_template(
            "register.html",
            error="Username already exists"
        )

    new_user = User(
        username=username,
        password=generate_password_hash(
            password
        )
    )

    db.session.add(new_user)

    db.session.commit()

    return redirect(
        url_for("login")
    )

# -----------------------------------
# DASHBOARD
# -----------------------------------
@app.route("/dashboard")
@token_required
def dashboard(current_user):

    return render_template(
        "dashboard.html",
        user=current_user
    )

# -----------------------------------
# EDIT PROFILE
# -----------------------------------
@app.route(
    "/edit-profile",
    methods=["GET", "POST"]
)
@token_required
def edit_profile(current_user):

    if request.method == "POST":

        new_username = request.form.get(
            "username"
        )

        existing = User.query.filter_by(
            username=new_username
        ).first()

        if existing and existing.id != current_user.id:

            return render_template(
                "edit_profile.html",
                user=current_user,
                error="Username already exists"
            )

        current_user.username = new_username

        db.session.commit()

        token = create_token(
            new_username
        )

        response = make_response(
            redirect(
                url_for("dashboard")
            )
        )

        response.set_cookie(
            "jwt_token",
            token,
            httponly=True,
            secure=False,
            samesite="Lax",
            max_age=1800
        )

        return response

    return render_template(
        "edit_profile.html",
        user=current_user
    )

# -----------------------------------
# CHANGE PASSWORD
# -----------------------------------
@app.route(
    "/change-password",
    methods=["GET", "POST"]
)
@token_required
def change_password(current_user):

    if request.method == "POST":

        old_password = request.form.get(
            "old_password"
        )

        new_password = request.form.get(
            "new_password"
        )

        if not check_password_hash(
            current_user.password,
            old_password
        ):

            return render_template(
                "change_password.html",
                error="Old password incorrect"
            )

        current_user.password = generate_password_hash(
            new_password
        )

        db.session.commit()

        return redirect(
            url_for("dashboard")
        )

    return render_template(
        "change_password.html"
    )

# -----------------------------------
# DELETE USER
# -----------------------------------
@app.route("/delete/<username>")
@token_required
def delete_user(current_user, username):

    if current_user.username != username:

        return jsonify({

            "message":
            "You can only delete your own account"

        }), 403

    user = User.query.filter_by(
        username=username
    ).first()

    if not user:

        return jsonify({

            "message":
            "User not found"

        }), 404

    db.session.delete(user)

    db.session.commit()

    response = make_response(
        jsonify({

            "message":
            f"User '{username}' deleted"

        })
    )

    response.delete_cookie(
        "jwt_token"
    )

    return response

# -----------------------------------
# API LOGIN
# -----------------------------------
@app.route(
    "/api/login",
    methods=["POST"]
)
def api_login():

    data = request.get_json() or {}

    username = data.get(
        "username"
    )

    password = data.get(
        "password"
    )

    user = User.query.filter_by(
        username=username
    ).first()

    if user and check_password_hash(
        user.password,
        password
    ):

        token = create_token(
            username
        )

        response = make_response(
            jsonify({

                "status": "success",
                "message": "Login successful"

            })
        )

        response.set_cookie(
            "jwt_token",
            token,
            httponly=True,
            secure=False,
            samesite="Lax",
            max_age=1800
        )

        return response

    return jsonify({

        "status": "failed",
        "message": "Invalid credentials"

    }), 401

# -----------------------------------
# API DASHBOARD
# -----------------------------------
@app.route("/api/dashboard")
@token_required
def api_dashboard(current_user):

    return jsonify({

        "message":
        f"Welcome {current_user.username}"

    })

# -----------------------------------
# API USERS
# -----------------------------------
@app.route("/api/users")
@token_required
def get_users(current_user):

    users = User.query.all()

    return jsonify({

        "logged_in_as":
        current_user.username,

        "users":
        [u.username for u in users]

    })

# -----------------------------------
# API EDIT PROFILE
# -----------------------------------
@app.route(
    "/api/edit-profile",
    methods=["POST"]
)
@token_required
def api_edit_profile(current_user):

    data = request.get_json() or {}

    new_username = data.get(
        "username"
    )

    if not new_username:

        return jsonify({

            "status": "failed",
            "message": "Username required"

        }), 400

    existing = User.query.filter_by(
        username=new_username
    ).first()

    if existing and existing.id != current_user.id:

        return jsonify({

            "status": "failed",
            "message": "Username already exists"

        }), 400

    current_user.username = new_username

    db.session.commit()

    token = create_token(
        new_username
    )

    response = make_response(
        jsonify({

            "status": "success",
            "message": "Profile updated"

        })
    )

    response.set_cookie(
        "jwt_token",
        token,
        httponly=True,
        secure=False,
        samesite="Lax",
        max_age=1800
    )

    return response

# -----------------------------------
# API CHANGE PASSWORD
# -----------------------------------
@app.route(
    "/api/change-password",
    methods=["POST"]
)
@token_required
def api_change_password(current_user):

    data = request.get_json() or {}

    old_password = data.get(
        "old_password"
    )

    new_password = data.get(
        "new_password"
    )

    if not old_password or not new_password:

        return jsonify({

            "status": "failed",
            "message": "All fields required"

        }), 400

    if not check_password_hash(
        current_user.password,
        old_password
    ):

        return jsonify({

            "status": "failed",
            "message": "Old password incorrect"

        }), 401

    current_user.password = generate_password_hash(
        new_password
    )

    db.session.commit()

    return jsonify({

        "status": "success",
        "message": "Password updated"

    })

# -----------------------------------
# LOGOUT
# -----------------------------------
@app.route("/logout")
def logout():

    response = make_response(
        redirect(url_for("login"))
    )

    response.delete_cookie("jwt_token")

    return response


@app.route("/api/logout")
def api_logout():

    response = make_response(
        redirect(url_for("login"))
    )

    response.delete_cookie("jwt_token")

    return response
# -----------------------------------
# RUN SERVER
# -----------------------------------
if __name__ == "__main__":

    app.run(
        debug=True
    )