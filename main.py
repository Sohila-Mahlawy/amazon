from flask import Flask, render_template, redirect, url_for, flash
from flask_bcrypt import Bcrypt
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin, LoginManager, login_user, login_required, logout_user, current_user
from flask_admin import Admin
from flask_admin.contrib.sqla import ModelView
from forms import RegistrationForm, LoginForm, ProductForm
from models import db, User, bcrypt, Product, Purchase

app = Flask(__name__)

# Load the configuration
app.config.from_object('config.Config')

# Initialize the extensions
db.init_app(app)
bcrypt.init_app(app)

login_manager = LoginManager(app)
login_manager.login_view = 'login'
login_manager.login_message_category = 'info'


with app.app_context():
    db.create_all()
# Define the user loader function for Flask-Login
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

class MyModelView(ModelView):
    def is_accessible(self):
        return True

# Initialize Flask-Admin
admin = Admin(app)
admin.add_view(MyModelView(User, db.session))
admin.add_view(MyModelView(Product, db.session))
admin.add_view(MyModelView(Purchase, db.session))

@app.route("/")
@app.route("/home")
def home():
    return render_template('home.html')

@app.route("/register", methods=["POST", "GET"])
def register():
    form = RegistrationForm()
    if form.validate_on_submit():
        email = form.email.data
        username = form.username.data
        password = form.password.data

        # Check if a user with the same email already exists
        existing_user = User.query.filter_by(email=email).first()
        if existing_user:
            flash('User with the same email already exists. Please choose a different email.', 'danger')
            return redirect(url_for('register'))

        new_user = User(email=email, username=username)
        new_user.set_password(password)

        db.session.add(new_user)
        db.session.commit()

        flash('Your account has been created!', 'success')
        return redirect(url_for('login'))

    return render_template("register.html", form=form)

@app.route("/login", methods=["GET", "POST"])
def login():
    # Redirect already logged-in users to the home page
    if current_user.is_authenticated:
        return redirect(url_for('home'))

    form = LoginForm()
    if form.validate_on_submit():
        email = form.email.data
        password = form.password.data

        user = User.query.filter_by(email=email).first()
        if user and user.check_password(password):
            login_user(user)
            return redirect(url_for('home'))

        flash('Login unsuccessful. Please check email and password', 'danger')

    return render_template("login.html", form=form)

@app.route("/logout")
def logout():
    logout_user()
    return redirect(url_for('home'))

@app.route('/products')
@login_required
def products():
    all_products = Product.query.all()
    return render_template("products.html", products=all_products)


@app.route('/buy/<int:product_id>', methods=['POST'])
@login_required
def buy(product_id):
    product = Product.query.get_or_404(product_id)
    success, message = product.buy(current_user.id)
    if success:
        flash(message, 'success')
    else:
        flash(message, 'danger')
    return redirect(url_for('products'))


# main.py
@app.route("/add_product", methods=['GET', 'POST'])
@login_required
def add_product():
    form = ProductForm()
    if form.validate_on_submit():
        Product.add(form.name.data, form.price.data, form.stock.data, current_user.id)
        flash('Product Added successfully!', 'success')
        return redirect(url_for('products'))  # Make sure you have a 'products' route

    return render_template("add_product.html", form=form)


@app.route("/purchases")
@login_required
def purchases():
    user_purchases = current_user.get_user_purchases()  # Use the method from the User model
    return render_template('purchases.html', purchases=user_purchases)

if __name__ == "__main__":
    app.run(debug=True)