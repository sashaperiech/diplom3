from flask import Flask, render_template, request, redirect, url_for, session, flash,abort
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from werkzeug.security import generate_password_hash, check_password_hash
import os
from werkzeug.utils import secure_filename
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField, TextAreaField, FloatField, SelectField, FileField
from wtforms.validators import DataRequired, Length, EqualTo, Email
from datetime import datetime

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'
app.config['SECRET_KEY'] = 'ваш_секретный_ключ'  
app.config['UPLOAD_FOLDER'] = 'static/uploads'
app.config['ALLOWED_EXTENSIONS'] = {'png', 'jpg', 'jpeg', 'gif'}

db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'

def allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in app.config['ALLOWED_EXTENSIONS']


class Order(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    address = db.Column(db.String(200), nullable=False)
    phone = db.Column(db.String(20), nullable=False)
    comment = db.Column(db.String(200))
    total_price = db.Column(db.Float, nullable=False)
    
    user = db.relationship('User', back_populates='orders')
    items = db.relationship('OrderItem', back_populates='order')

class ProfileForm(FlaskForm):
    username = StringField('Имя пользователя', validators=[DataRequired(), Length(min=4, max=25)])
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Новый пароль', validators=[Length(min=6)])
    submit = SubmitField('Сохранить изменения')


class OrderItem(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    order_id = db.Column(db.Integer, db.ForeignKey('order.id'), nullable=False)
    product_id = db.Column(db.Integer, db.ForeignKey('product.id'), nullable=False)
    quantity = db.Column(db.Integer, nullable=False)
    
    order = db.relationship('Order', back_populates='items')
    product = db.relationship('Product')


class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), unique=True)
    email = db.Column(db.String(100), unique=True)
    password = db.Column(db.String(100))
    is_admin = db.Column(db.Boolean, default=False)
    is_active = db.Column(db.Boolean, default=True)  # Атрибут активности пользователя
    
    orders = db.relationship('Order', back_populates='user')

    def __repr__(self):
        return f'<User {self.username}>'

    def get_id(self):
        return str(self.id) 

class RegistrationForm(FlaskForm):
    username = StringField('Имя пользователя', validators=[DataRequired(), Length(min=4, max=25)])
    password = PasswordField('Пароль', validators=[DataRequired(), Length(min=6)])
    confirm_password = PasswordField('Подтвердите пароль', validators=[DataRequired(), EqualTo('password')])
    submit = SubmitField('Зарегистрироваться')

class LoginForm(FlaskForm):
    username = StringField('Имя пользователя', validators=[DataRequired()])
    password = PasswordField('Пароль', validators=[DataRequired()])
    submit = SubmitField('Войти')

class ProductForm(FlaskForm):  # Новая форма для товаров
    name = StringField('Название', validators=[DataRequired()])
    description = TextAreaField('Описание')
    price = FloatField('Цена', validators=[DataRequired()])
    category = SelectField('Категория', choices=[
        ('Сувениры', 'Сувениры'),
        ('Книги', 'Книги'),
        ('Ремесла', 'Ремесла')
    ])
    image = FileField('Изображение')
    submit = SubmitField('Добавить')

class ProfileForm(FlaskForm):
    username = StringField('Имя пользователя', validators=[DataRequired(), Length(min=4, max=25)])
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Новый пароль', validators=[Length(min=6)])
    submit = SubmitField('Сохранить изменения')


class Product(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    description = db.Column(db.String(300))
    price = db.Column(db.Float)
    category = db.Column(db.String(50))
    image = db.Column(db.String(100))

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

@app.route('/')
def index():
    products = Product.query.limit(4).all()
    return render_template('index.html', products=products)

@app.route('/privacy-policy')
def privacy_policy():
    return render_template('privacy_policy.html')
@app.route('/about_us')
def about_us():
    return render_template('about_us.html')

@app.route('/change_profile', methods=['GET', 'POST'])
@login_required
def change_profile():
    form = ProfileForm()
    if form.validate_on_submit():

       
        if form.password.data:
            hashed_pw = generate_password_hash(form.password.data)
            current_user.password = hashed_pw
       
        current_user.username = form.username.data
        current_user.email = form.email.data
        
       
        db.session.commit()
        
        flash('Ваш профиль успешно обновлен!', 'success')
        return redirect(url_for('change_profile'))

    
    form.username.data = current_user.username
    form.email.data = current_user.email

    return render_template('change_profile.html', form=form)

@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegistrationForm()
    if form.validate_on_submit():
        hashed_pw = generate_password_hash(form.password.data)
        user = User(username=form.username.data, password=hashed_pw, is_admin=False)
        db.session.add(user)
        db.session.commit()
        flash('Регистрация успешна! Теперь вы можете войти.', 'success')
        return redirect(url_for('login'))
    return render_template('register.html', form=form)

@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user and check_password_hash(user.password, form.password.data):
            login_user(user)
            next_page = request.args.get('next')
            return redirect(next_page) if next_page else redirect(url_for('index'))
        flash('Неверный логин или пароль', 'danger')
    return render_template('login.html', form=form)

from flask import redirect, url_for, flash

@app.route('/delete_product/<int:product_id>', methods=['POST'])
@login_required
def delete_product(product_id):
    product = Product.query.get_or_404(product_id)
    
    if not current_user.is_admin:
        flash('Нет доступа для удаления', 'danger')
        return redirect(url_for('products'))
    

    db.session.delete(product)
    db.session.commit()
    
    flash('Товар успешно удалён', 'success')
    return redirect(url_for('products'))

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('index'))

@app.route('/products')
def products():
    category = request.args.get('category')
    if category:
        products = Product.query.filter_by(category=category).all()
    else:
        products = Product.query.all()
    return render_template('products.html', products=products)

@app.route('/add_product', methods=['GET', 'POST'])
@login_required
def add_product():
    
    if not current_user.is_admin:
        abort(403)  
    
    form = ProductForm()  
    
    if form.validate_on_submit():
        image_path = None
        if form.image.data:
            file = form.image.data
            if allowed_file(file.filename):
                filename = secure_filename(file.filename)
                file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
                image_path = f"uploads/{filename}"
        
        new_product = Product(
            name=form.name.data,
            description=form.description.data,
            price=form.price.data,
            category=form.category.data,
            image=image_path
        )
        db.session.add(new_product)
        db.session.commit()
        flash('Товар успешно добавлен!', 'success')
        return redirect(url_for('products'))
    
    return render_template('add_product.html', form=form)

from flask import render_template
from flask_login import login_required, current_user

@app.route('/order')
@login_required
def order():
    if current_user.is_admin:
        orders = Order.query.all()
    else:
        orders = Order.query.filter_by(user_id=current_user.id).all()
    return render_template('order.html', orders=orders)

@app.route('/checkout', methods=['POST'])
@login_required
def checkout():
    
    if 'cart' not in session or len(session['cart']) == 0:
        flash('Ваша корзина пуста', 'danger')
        return redirect(url_for('cart'))

    
    address = request.form['address']
    phone = request.form['phone']
    comment = request.form.get('comment', '')

    
    total_price = 0
    new_order = Order(user_id=current_user.id, address=address, phone=phone, comment=comment, total_price=total_price)
    db.session.add(new_order)
    db.session.commit()

   
    for product_id, quantity in session['cart'].items():
        product = Product.query.get(product_id)
        total_price += product.price * quantity
        order_item = OrderItem(order_id=new_order.id, product_id=product.id, quantity=quantity)
        db.session.add(order_item)

    
    new_order.total_price = total_price
    db.session.commit()

   
    session['cart'] = {}

    flash('Ваш заказ успешно оформлен!', 'success')

    return redirect(url_for('order'))  # Перенаправляем на страницу заказов
@app.route('/product/<int:id>')
def product_detail(id):
    product = Product.query.get_or_404(id)
    
    
    similar_products = Product.query.filter(
        Product.category == product.category,
        Product.id != product.id
    ).limit(3).all()
    return render_template('product_detail.html', 
                         product=product,
                         similar_products=similar_products)
@app.route('/cart', methods=['GET', 'POST'])
@login_required
def cart():
    if 'cart' not in session:
        session['cart'] = {}

    if request.method == 'POST':
        product_id = request.form.get('product_id')
        quantity = request.form.get('quantity', 1)
        try:
            quantity = int(quantity)
            if quantity < 1:
                quantity = 1
        except ValueError:
            quantity = 1

        if product_id:
            if product_id in session['cart']:
                session['cart'][product_id] += quantity
            else:
                session['cart'][product_id] = quantity
            session.modified = True
            flash('Товар добавлен в корзину', 'success')
        return redirect(url_for('cart'))

    product_ids = list(session['cart'].keys())
    cart_products = Product.query.filter(Product.id.in_(product_ids)).all()
    quantities = session['cart']
    total_price = sum(product.price * quantities.get(str(product.id), 0) for product in cart_products)

    return render_template('cart.html',
                           cart_products=cart_products,
                           total_price=total_price,
                           quantities=quantities)

@app.route('/remove_from_cart/<int:product_id>')
@login_required
def remove_from_cart(product_id):
    product_id_str = str(product_id)
    if 'cart' in session and product_id_str in session['cart']:
        
        if session['cart'][product_id_str] > 1:
            session['cart'][product_id_str] -= 1
        else:
            session['cart'].pop(product_id_str)
        session.modified = True
        flash('Товар обновлен в корзине', 'info')
    return redirect(url_for('cart'))

@app.route('/user_page')
@login_required
def user_page():
    return render_template('user_page.html')

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
        if not os.path.exists(app.config['UPLOAD_FOLDER']):
            os.makedirs(app.config['UPLOAD_FOLDER'])
    app.run(debug=True)
