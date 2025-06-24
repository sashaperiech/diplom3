from main import db, User,app
from werkzeug.security import generate_password_hash, check_password_hash

def create_admin():
    username = 'admin1'
    password = 'admin'

    with app.app_context():
        if User.query.filter_by(username=username).first():
            print("Пользователь admin уже существует.")
            return
        admin = User(
            username=username,
            password=generate_password_hash(password),
            is_admin=True
        )
        db.session.add(admin)
        db.session.commit()
        print("Администратор создан.")

if __name__ == '__main__':
    create_admin()