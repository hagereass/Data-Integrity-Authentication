from flask import Flask, request, jsonify, send_file
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity
import pyotp
import qrcode
import io
import datetime

app = Flask(__name__)

# إعداد MySQL
app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql+pymysql://root:@localhost/data_integrity_task'
app.config['JWT_SECRET_KEY'] = 'your_jwt_secret_key'
db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
jwt = JWTManager(app)

# نموذج المستخدم
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(100), unique=True, nullable=False)
    password = db.Column(db.String(255), nullable=False)
    secret_2fa = db.Column(db.String(255), nullable=True)

# نموذج المنتجات
class Product(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    description = db.Column(db.Text)
    price = db.Column(db.Float, nullable=False)
    quantity = db.Column(db.Integer, nullable=False)

# إنشاء الجداول في قاعدة البيانات
with app.app_context():
    db.create_all()

# تسجيل مستخدم جديد
@app.route('/signup', methods=['POST'])
def signup():
    data = request.json
    if User.query.filter_by(username=data['username']).first():
        return jsonify({'message': 'Username already exists'}), 400

    hashed_password = bcrypt.generate_password_hash(data['password']).decode('utf-8')
    new_user = User(username=data['username'], password=hashed_password)
    db.session.add(new_user)
    db.session.commit()
    return jsonify({'message': 'User registered successfully'}), 201

# تسجيل الدخول وعرض QR Code
@app.route('/login', methods=['POST'])
def login():
    data = request.json
    user = User.query.filter_by(username=data['username']).first()

    if not user or not bcrypt.check_password_hash(user.password, data['password']):
        return jsonify({'message': 'Invalid username or password'}), 401

    if not user.secret_2fa:
        secret_2fa = pyotp.random_base32()
        user.secret_2fa = secret_2fa
        db.session.commit()
    else:
        secret_2fa = user.secret_2fa

    uri = pyotp.totp.TOTP(secret_2fa).provisioning_uri(name=user.username, issuer_name='Data_Integrity_2FA')

    # تحسين حجم QR Code
    qr = qrcode.QRCode(
        version=2,  
        error_correction=qrcode.constants.ERROR_CORRECT_L,
        box_size=5,  
        border=2  
    )
    qr.add_data(uri)
    qr.make(fit=True)
    img = qr.make_image(fill='black', back_color='white')

    img_io = io.BytesIO()
    img.save(img_io)
    img_io.seek(0)

    return send_file(img_io, mimetype='image/png')

# التحقق من 2FA والحصول على `JWT Token`
@app.route('/verify-2fa', methods=['POST'])
def verify_2fa():
    data = request.json
    user = User.query.filter_by(username=data['username']).first()

    if not user or not user.secret_2fa:
        return jsonify({'message': 'User not found or 2FA not set up'}), 404

    totp = pyotp.TOTP(user.secret_2fa)
    if not totp.verify(data['code']):
        return jsonify({'message': 'Invalid 2FA code'}), 401

    access_token = create_access_token(identity=str(user.id), expires_delta=datetime.timedelta(hours=1))
    return jsonify({'token': access_token})

# إضافة منتج (`JWT Required`)
@app.route('/products', methods=['POST'])
@jwt_required()
def create_product():
    data = request.json
    new_product = Product(name=data['name'], description=data.get('description', ''), price=data['price'], quantity=data['quantity'])
    db.session.add(new_product)
    db.session.commit()
    return jsonify({'message': 'Product added successfully'}), 201

# عرض المنتجات (`JWT Required`)
@app.route('/products', methods=['GET'])
@jwt_required()
def get_products():
    products = Product.query.all()
    return jsonify([{'id': p.id, 'name': p.name, 'description': p.description, 'price': p.price, 'quantity': p.quantity} for p in products])

# تحديث منتج (`JWT Required`)
@app.route('/products/<int:product_id>', methods=['PUT'])
@jwt_required()
def update_product(product_id):
    product = Product.query.get(product_id)
    if not product:
        return jsonify({'message': 'Product not found'}), 404

    data = request.json
    if 'name' in data:
        product.name = data['name']
    if 'description' in data:
        product.description = data['description']
    if 'price' in data:
        product.price = data['price']
    if 'quantity' in data:
        product.quantity = data['quantity']

    db.session.commit()
    return jsonify({'message': 'Product updated successfully'})

# حذف منتج (`JWT Required`)
@app.route('/products/<int:product_id>', methods=['DELETE'])
@jwt_required()
def delete_product(product_id):
    product = Product.query.get(product_id)
    if not product:
        return jsonify({'message': 'Product not found'}), 404

    db.session.delete(product)
    db.session.commit()
    return jsonify({'message': 'Product deleted successfully'})

if __name__ == '__main__':
    app.run(debug=True)
