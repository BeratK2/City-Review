from flask import Flask, render_template, session, url_for, redirect, request, jsonify, flash
from flask_sqlalchemy import SQLAlchemy
from flask_login import (
    UserMixin,
    login_user,
    LoginManager,
    login_required,
    logout_user,
    current_user,
)
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import InputRequired, Length, ValidationError
from flask_bcrypt import Bcrypt
from city import cities_data
from sqlalchemy.orm import sessionmaker


# Flask and db setup
app = Flask(__name__)
app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///database.db"
app.config["SECRET_KEY"] = "abcsecretkey"
db = SQLAlchemy()
db.init_app(app)
bcrypt = Bcrypt(app)


# Login Manager
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = "login"


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))



# User Table Schema
class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(20), nullable=False)
    password = db.Column(db.String(80), nullable=False)


# City Table Schema
class City(db.Model):
    name = db.Column(db.String(100), primary_key=True)
    avg_safety = db.Column(db.Integer)
    avg_transportation = db.Column(db.Integer)
    avg_dining = db.Column(db.Integer)
    avg_attractions = db.Column(db.Integer)
    avg_weather = db.Column(db.Integer)
    avg_social = db.Column(db.Integer)
    avg_affordability = db.Column(db.Integer)
    ratings = db.Column(db.JSON)



# Register Form Class
class RegisterForm(FlaskForm):
    username = StringField(
        validators=[InputRequired(), Length(min=4, max=20)],
        render_kw={"placeholder": "Username"},
    )

    # Method to check if username already exists
    def validate_username(self, username):
        existing_user_username = User.query.filter_by(username=username.data).first()
        if existing_user_username:
            raise ValidationError(
                "That username already exists. Please choose a different one."
            )

    password = PasswordField(
        validators=[InputRequired(), Length(min=8, max=20)],
        render_kw={"placeholder": "Password"},
    )

    submit = SubmitField("Register")


# Login Form Class
class LoginForm(FlaskForm):
    username = StringField(
        validators=[InputRequired(), Length(min=4, max=20)],
        render_kw={"placeholder": "Username"},
    )

    password = PasswordField(
        validators=[InputRequired(), Length(min=8, max=20)],
        render_kw={"placeholder": "Password"},
    )

    submit = SubmitField("Login")



#*MAIN ROUTES*#
# Main route
@app.route("/")
def home():
    search_query = request.form.get("searchInput")

    if search_query is not None:
        search_query = search_query.lower()

    # Query the database for cities
    matching_cities = City.query.filter(City.name.ilike(f"%{search_query}%")).all()

    # Convert city objects to a list of strings
    results = [city.name for city in matching_cities]

    return render_template("home.html", results=results)


# Route to return all cities
@app.route("/all_cities")
def all_cities():
    # Query the database for all city names
    all_city_names = [city.name for city in City.query.all()]
    return jsonify(all_city_names)


# Route to search for cities based on input
@app.route("/search", methods=["POST"])
def search():
    search_query = request.form.get("searchInput")

    # Query the database for cities
    matching_cities = City.query.filter(City.name.ilike(f"%{search_query}%")).all()

    # Assume the first result is the selected city (you may want to add more logic here)
    selected_city = matching_cities[0] if matching_cities else None

    # Update avg_safety to 4 for all matching cities
    if selected_city:
        db.session.commit()

        # Store the selected city name in the session
        session['selected_city_name'] = selected_city.name

    # Pass the selected city name to the 'city.html' template
    return render_template("city.html", selected_city=selected_city)


#Review Route
@app.route("/review", methods=["GET", "POST"])
#@login_required
def review():
    # Ensure the user is logged in
    if not current_user.is_authenticated:
        # If not logged in, redirect to the login page
        return redirect(url_for('login'))  # Assuming your login route is named 'login'

    # Retrieve the selected city name from the session or wherever you stored it
    selected_city_name = session.get('selected_city_name')  # Adjust this based on your actual implementation

    # Render the 'review.html' template with the selected city name
    return render_template("review.html", selected_city_name=selected_city_name)

# Login route
@app.route("/dashboard", methods=["GET", "POST"])
def dashboard():
    return render_template("dashboard.html")


#Submit Review Route
@app.route("/submit_review", methods=["POST"])
#@login_required
def submit_review():
    # Retrieve form data
    safety = int(request.form.get("safety"))
    transportation = int(request.form.get("transportation"))
    dining = int(request.form.get("dining"))
    attractions = int(request.form.get("attractions"))
    weather = int(request.form.get("weather"))
    social = int(request.form.get("social"))  # Corrected key to 'social'
    affordability = int(request.form.get("affordability"))
    review = request.form.get("review")

    # Create a dictionary for the new ratings
    new_ratings = {
        "safety": safety,
        "transportation": transportation,
        "dining": dining,
        "attractions": attractions,
        "weather": weather,
        "social": social,
        "affordability": affordability,
        "review": review
    }

      # Retrieve the selected city name from the session
    selected_city_name = session.get('selected_city_name')

    # Check if the selected city name exists
    if selected_city_name:
        # Query the database to get the corresponding City object
        selected_city = City.query.filter_by(name=selected_city_name).first()

        # Check if the selected city object exists
        if selected_city:
            # Commit the changes to the database

            print(f"Selected City Name: {selected_city.name}")
            print(f"Selected City Ratings Before Update: {selected_city.ratings}")

            # Update the ratings JSON column in the database
            selected_city_ratings = selected_city.ratings or {}
            selected_city_ratings.update(new_ratings)

            # Use the merge function to update the existing JSON column
            selected_city.ratings = db.session.merge(selected_city.ratings, new_ratings)
            print(f"Selected City Ratings After Update: {selected_city.ratings}")
            
            db.session.commit()

            updated_city = City.query.get(selected_city_name)
            print(f"City Ratings in the Database: {updated_city.ratings}")  

            flash("Review submitted successfully!", "success")
        else:
            flash("Error: No selected city found.", "error")
    else:
        flash("Error: No selected city name found in the session.", "error")

    # Redirect back to the review page
    return redirect(url_for('review'))


#*AUTHENTICATION ROUTES*#
# Login route
@app.route("/login", methods=["GET", "POST"])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user:
            if bcrypt.check_password_hash(user.password, form.password.data):
                login_user(user)
                return redirect(url_for("dashboard"))
    return render_template("login.html", form=form)


# Register route
@app.route("/register", methods=["GET", "POST"])
def register():
    form = RegisterForm()

    if form.validate_on_submit():
        hashed_password = bcrypt.generate_password_hash(form.password.data)
        new_user = User(username=form.username.data, password=hashed_password)
        db.session.add(new_user)
        db.session.commit()
        return redirect(url_for("login"))
    return render_template("register.html", form=form)


if __name__ == "__main__":
    app.run(debug=True)
