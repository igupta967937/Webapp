from flask_ngrok import run_with_ngrok
from flask_marshmallow import Marshmallow
from flask import Flask, render_template, redirect, url_for, session, flash, request,jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate, MigrateCommand
from flask_script import Manager
from flask_uploads import UploadSet, configure_uploads, IMAGES
from flask_wtf import FlaskForm
from wtforms import StringField, IntegerField, TextAreaField, HiddenField, SelectField, SubmitField, PasswordField
from flask_wtf.file import FileField, FileAllowed
from flask_login import login_user,login_required,logout_user,current_user
import random
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import UserMixin
from flask_login import LoginManager
from myprojects.forms import LoginForm, RegistrationForm, SearchForm, DeleteForm
from flask_bcrypt import Bcrypt
# The user_loader decorator whill allow the flask to load the current logged in user.
# and will also grab their id.
import stripe
import datetime
from flask_mail import Mail
from wtforms.validators import DataRequired, Length, Email, EqualTo, ValidationError
from datetime import datetime
from itsdangerous import TimedJSONWebSignatureSerializer as Serializer
from flask_mail import Message
import json

app = Flask(__name__)
run_with_ngrok(app)   #starts ngrok when the app is run
mail = Mail(app)
bcrypt = Bcrypt(app)
app.config['MAIL_SERVER'] = 'smtp.googlemail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = 'clintondelvin023@gmail.com'
app.config['MAIL_PASSWORD'] = 'C500701d$123'
mail = Mail(app)









pub_key = 'pk_test_ehAVPFKRm6CKrzTW4F707sqF00zKTuDok9'
# This is a public key that one can obtain from the stripe website if you wish to carry on with any credit card transactions.


secret_key = 'sk_test_wawTZFb80biOYE4xP5OnpZke00WxjldcSP'
# This is a secret key that one can obtain from the stripe website if you wish to carry on with any credit card transactions.
stripe.api_key=secret_key
# The same secret key is then passed to the stripe to carry on the further processes.


#This line indicates that we start the python web application from this file.

photos = UploadSet('photos', IMAGES)

app.config['UPLOADED_PHOTOS_DEST'] = 'images'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///trendy.db'  #Location and the name of the db is specified over here.
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

app.config['SECRET_KEY'] = 'mysecret'  #This is a secret key that we can define, for flask_wtf to work we need to specify a secret key.

configure_uploads(app, photos)

db = SQLAlchemy(app)
migrate = Migrate(app, db)
login_manager = LoginManager() #We store the login mananger function imported above and store it in a variable named as login_manager
login_manager.init_app(app)
login_manager.login_view = "login1"
#if the user is not authenticated then he/she will not be able to navigate to any other screen apart from the login screen.
manager = Manager(app)
manager.add_command('db', MigrateCommand)
ma = Marshmallow(app)
from flask_sqlalchemy import SQLAlchemy
from flask_marshmallow import Marshmallow

db = SQLAlchemy(app)
ma = Marshmallow(app) 
class Product(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(50), unique=True)
    price = db.Column(db.Integer) #in cents
    stock = db.Column(db.Integer)
    description = db.Column(db.String(500))
    image = db.Column(db.String(100))

    orders = db.relationship('Order_Item', backref='product', lazy=True)

class Order(db.Model):

    __tablename__ = 'order'
    id = db.Column(db.Integer, primary_key=True)
    reference = db.Column(db.String(5))
    first_name = db.Column(db.String(20))
    last_name = db.Column(db.String(20))
    phone_number = db.Column(db.Integer)
    email = db.Column(db.String(50))
    address = db.Column(db.String(100))
    city = db.Column(db.String(100))
    state = db.Column(db.String(20))
    country = db.Column(db.String(20))
    status = db.Column(db.String(10))
    payment_type = db.Column(db.String(10))
    items = db.relationship('Order_Item', backref='order', lazy=True)

    def order_total(self):
        return db.session.query(db.func.sum(Order_Item.quantity * Product.price)).join(Product).filter(Order_Item.order_id == self.id).scalar()

    def quantity_total(self):
        return db.session.query(db.func.sum(Order_Item.quantity)).filter(Order_Item.order_id == self.id).scalar()

class Order_Item(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    order_id = db.Column(db.Integer, db.ForeignKey('order.id'))
    product_id = db.Column(db.Integer, db.ForeignKey('product.id'))
    quantity = db.Column(db.Integer)

class AddProduct(FlaskForm):
    name = StringField('Name')
    price = IntegerField('Price')
    stock = IntegerField('Stock')
    description = TextAreaField('Description')
    image = FileField('Image', validators=[FileAllowed(IMAGES, 'Only images are accepted.')])

class AddToCart(FlaskForm):
    quantity = IntegerField('Quantity')
    id = HiddenField('ID')

class Checkout(FlaskForm):
    first_name = StringField('First Name')
    last_name = StringField('Last Name')
    phone_number = StringField('Number')
    email = StringField('Email')
    address = StringField('Address')
    city = StringField('City')
    state = SelectField('State', choices=[('CA', 'Dublin'), ('CR', 'Cork'), ('GL', 'Galway')])
    country = SelectField('Country', choices=[('IR', 'Ireland'), ('UK', 'United Kingdom'), ('IN', 'India')])
    payment_type = SelectField('Payment Type', choices=[('CC', 'Credit Card'), ('DC', 'Debit Card')])


class RequestResetForm(FlaskForm):
    email = StringField('Email',
                        validators=[DataRequired(), Email()])
    submit = SubmitField('Request Password Reset')

    def validate_email(self, email):
        user = User.query.filter_by(email=email.data).first()
        if user is None:
            raise ValidationError('There is no account with that email. You must register first.')


class ResetPasswordForm(FlaskForm):
    password = PasswordField('Password', validators=[DataRequired()])
    confirm_password = PasswordField('Confirm Password',
                                     validators=[DataRequired(), EqualTo('password')])
    submit = SubmitField('Reset Password')

class Export(FlaskForm):
    submit = SubmitField('Export Product Data')

class ProductSchema(ma.ModelSchema):
    class Meta:
        model = Product

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(user_id)

class User(db.Model, UserMixin):

    # Create a table in the database
    __tablename__ = 'users'

    id = db.Column(db.Integer, primary_key = True)
    email = db.Column(db.String(64), unique=True, index=True)
    first_name = db.Column(db.String(64))
    last_name = db.Column(db.String(64))
    username = db.Column(db.String(64), unique=True, index=True)
    password_hash = db.Column(db.String(128))

    def __init__(self, email,first_name,last_name, username, password):
        self.email = email
        self.first_name = first_name
        self.last_name = last_name
        self.username = username
        self.password_hash = generate_password_hash(password)

    def get_reset_token(self, expires_sec=1800):
        s = Serializer(app.config['SECRET_KEY'], expires_sec)
        return s.dumps({'user_id': self.id}).decode('utf-8')

    def check_password(self,password):
        return check_password_hash(self.password_hash,password)

    @staticmethod
    def verify_reset_token(token):
        s = Serializer(app.config['SECRET_KEY'])
        try:
            user_id = s.loads(token)['user_id']
        except:
            return None
        return User.query.get(user_id)

    def __repr__(self):
        return f"User('{self.username}', '{self.email}')"

def handle_cart():
    products = []
    grand_total = 0
    index = 0
    quantity_total = 0

    for item in session['cart']:
        product = Product.query.filter_by(id=item['id']).first()
        print(product)
        quantity = int(item['quantity'])
        total = quantity * product.price
        grand_total += total

        quantity_total += quantity

        products.append({'id' : product.id, 'name' : product.name, 'price' :  product.price, 'image' : product.image, 'quantity' : quantity, 'total': total, 'index': index})
        index += 1

    grand_total_plus_shipping = grand_total + 10

    return products, grand_total, grand_total_plus_shipping, quantity_total

@app.route('/',methods=['GET','POST'])
def home():
    form=Export()
    if form.validate_on_submit():
        products = Product.query.all()
        print(type(products))
        print(len(products))
        dict1={}
        list1=[]
        list1=[{"id":i.id,"name":i.name,"price":i.price,"stock":i.stock,"description":i.description,"image":i.image} for i in products]
        r=json.dumps(list1, indent=3)
        print(r)
        f= open("testing.txt","w+")
        f.write(r)
        f.close()
        db.session.commit()
    return render_template('home.html',form=form)


@app.route('/jasonobject')
def jasonobject():
    products = Product.query.all()
    products_schema = ProductSchema(many=True)
    output = products_schema.dump(products)
    return jsonify(output)


@app.route('/welcome')
@login_required
def welcome_user():
    return render_template('welcome_user.html')


@app.route('/products',methods=['GET','POST'])
@login_required
def index():
    form=SearchForm()
    if form.validate_on_submit():
        products = Product.query.filter_by(name=form.name.data)
        db.session.commit()
        flash('Below is your search result','success')
        return render_template('index.html', products=products,form=form)
    else:
        products = Product.query.all()
        db.session.commit()
        return render_template('index.html', products=products,form=form)

@app.route('/product/<id>')
def product(id):
    product = Product.query.filter_by(id=id).first()

    form = AddToCart()
    return render_template('view-product.html', product=product, form=form)

@app.route('/quick-add/<id>')
def quick_add(id):
    if 'cart' not in session:
        session['cart'] = []

    session['cart'].append({'id' : id, 'quantity' : 1})
    session.modified = True
    flash('Product added successfully to the cart','success')
    return redirect(url_for('index'))

@app.route('/add-to-cart', methods=['POST'])
@login_required
def add_to_cart():
    if 'cart' not in session:
        session['cart'] = []

    form = AddToCart()

    if form.validate_on_submit():

        session['cart'].append({'id' : form.id.data, 'quantity' : form.quantity.data})
        session.modified = True

    return redirect(url_for('index'))

@app.route('/cart')
@login_required
def cart():
    products, grand_total, grand_total_plus_shipping, quantity_total = handle_cart()

    return render_template('cart.html', products=products, grand_total=grand_total, grand_total_plus_shipping=grand_total_plus_shipping, quantity_total=quantity_total)

@app.route('/remove-from-cart/<index>')
def remove_from_cart(index):
    del session['cart'][int(index)]
    session.modified = True
    flash('One Product successfully removed from the cart','danger')
    return redirect(url_for('cart'))

@app.route('/checkout', methods=['GET', 'POST'])
@login_required
def checkout():
    form = Checkout()

    products, grand_total, grand_total_plus_shipping, quantity_total = handle_cart()

    if form.validate_on_submit():

        order = Order()
        form.populate_obj(order)
        order.reference = ''.join([random.choice('ABCDE') for _ in range(5)])
        order.status = 'PENDING'

        for product in products:
            order_item = Order_Item(quantity=product['quantity'], product_id=product['id'])
            order.items.append(order_item)

            product = Product.query.filter_by(id=product['id']).update({'stock' : Product.stock - product['quantity']})
        customer = stripe.Customer.create(email=request.form['stripeEmail'], source=request.form['stripeToken'])
        print(request.form)
        products, grand_total, grand_total_plus_shipping, quantity_total = handle_cart()
        charge = stripe.Charge.create(
            customer=customer.id,
            amount=grand_total_plus_shipping*100,
            currency='usd',
            description='The Product'
        )
        db.session.add(order)
        db.session.commit()
        session['cart'] = []
        session.modified = True
        flash('Your order has been successfully submitted and payment is also done','success')
        return redirect(url_for('index'))

    return render_template('checkout.html', form=form, grand_total=grand_total, grand_total_plus_shipping=grand_total_plus_shipping, quantity_total=quantity_total, pub_key=pub_key)

@app.route('/pay', methods=['POST'])
@login_required
def pay():

    customer = stripe.Customer.create(email=request.form['stripeEmail'], source=request.form['stripeToken'])
    print(request.form)
    products, grand_total, grand_total_plus_shipping, quantity_total = handle_cart()
    charge = stripe.Charge.create(
        customer=customer.id,
        amount=grand_total_plus_shipping*100,
        currency='usd',
        description='The Product'
    )

    return 'successfully Done'


@app.route('/admin')
@login_required
def admin():
    products = Product.query.all()
    products_in_stock = Product.query.filter(Product.stock > 0).count()

    orders = Order.query.all()

    return render_template('admin/index.html', admin=True, products=products, products_in_stock=products_in_stock, orders=orders)

@app.route('/admin/add', methods=['GET', 'POST'])
@login_required
def add():
    form = AddProduct()

    if form.validate_on_submit():
        image_url = photos.url(photos.save(form.image.data))

        new_product = Product(name=form.name.data, price=form.price.data, stock=form.stock.data, description=form.description.data, image=image_url)

        db.session.add(new_product)
        db.session.commit()
        flash('Product added to the database successfully and can be found in the product page','success')
        return redirect(url_for('admin'))
    return render_template('admin/add-product.html', admin=True, form=form)

@app.route('/admin/delete', methods=['GET', 'POST'])
@login_required
def delete():
    form = DeleteForm()
    print(current_user.username)
    if form.validate_on_submit():
        del_product = Product.query.filter_by(name=form.name.data)
        Product.query.filter(Product.name==form.name.data).delete()
        db.session.commit()
        flash('Product has been deleted successfully from the database','danger')
        return redirect(url_for('admin'))

    return render_template('admin/delete-product.html', admin=True, form=form)
@app.route('/admin/order/<order_id>')
def order(order_id):
    order = Order.query.filter_by(id=int(order_id)).first()

    return render_template('admin/view-order.html', order=order, admin=True)



@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('Thank you for using our services. Please do visit us again','success')
    return redirect(url_for('home'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        # Grab the user from our User Models table
        user = User.query.filter_by(email=form.email.data).first()


        if user.check_password(form.password.data) and user is not None:
            #Log in the user

            login_user(user)
            flash('Logged in successfully bro.')
            next = request.args.get('next')

            # So let's now check if that next exists or no, otherwise it'll go to
            # the welcome page.
            return redirect(url_for('welcome_user'))
    return render_template('login.html', form=form)

@app.route('/login1', methods=['GET', 'POST'])
def login1():
    form = LoginForm()
    if form.validate_on_submit():
        # Grab the user from our User Models table
        user = User.query.filter_by(email=form.email.data).first()
        if user.check_password(form.password.data) and user is not None:
            #Log in the user

            login_user(user)
            flash('Logged in successfully','success')
            next = request.args.get('next')

            # So let's now check if that next exists or no, otherwise it'll go to
            # the welcome page.
            return redirect(url_for('welcome_user'))
        else:
            flash('Login again as the username of password was incorrect','danger')
            return redirect(url_for('login1'))
    return render_template('login1.html', form=form)

@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegistrationForm()

    if form.validate_on_submit():
        user = User(email=form.email.data,
                    first_name=form.first_name.data,
                    last_name=form.last_name.data,
                    username=form.username.data,
                    password=form.password.data)

        db.session.add(user)
        db.session.commit()
        flash('Thanks for registering! Now you can login!','success')
        return redirect(url_for('login1'))
    return render_template('register.html', form=form)



def send_reset_email(user):
    token = user.get_reset_token()
    msg = Message('Password Reset Request',
                  sender='noreply@demo.com',
                  recipients=[user.email])
    msg.body = f'''To reset your password, visit the following link:
{url_for('reset_token', token=token, _external=True)}
If you did not make this request then simply ignore this email and no changes will be made.
'''
    mail.send(msg)


@app.route("/reset_password", methods=['GET', 'POST'])
def reset_request():
    if current_user.is_authenticated:
        return redirect(url_for('home'))
    form = RequestResetForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        send_reset_email(user)
        flash('An email has been sent with instructions to reset your password.', 'info')
        return redirect(url_for('login1'))
    return render_template('reset_request.html', title='Reset Password', form=form)


@app.route("/reset_password/<token>", methods=['GET', 'POST'])
def reset_token(token):
    if current_user.is_authenticated:
        return redirect(url_for('home'))
    user = User.verify_reset_token(token)
    if user is None:
        flash('That is an invalid or expired token', 'warning')
        return redirect(url_for('reset_request'))
    form = ResetPasswordForm()
    if form.validate_on_submit():
        password_hash = generate_password_hash(form.password.data)
        user.password_hash = password_hash
        db.session.commit()
        flash('Your password has been updated! You are now able to log in', 'success')
        return redirect(url_for('login1'))
    return render_template('reset_token.html', title='Reset Password', form=form)

@app.errorhandler(404)
def error404(error):
    return render_template('error404.html')

@app.errorhandler(500)
def error500(error):
    return render_template('error500.html')

@app.errorhandler(405)
def error405(error):
    return render_template('error405.html')

if __name__ == '__main__':
    app.run()
