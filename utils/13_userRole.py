from flask import Flask, render_template, redirect, url_for, request, flash, current_app
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from flask_principal import Principal, Permission, RoleNeed, Identity, AnonymousIdentity, identity_loaded, identity_changed

app = Flask(__name__)
app.secret_key = 'your_secret_key'

# Flask-Login setup
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

# Flask-Principal setup
principals = Principal(app)

# Permissions
admin_permission = Permission(RoleNeed('admin'))
user_permission = Permission(RoleNeed('user'))

# User model
class User(UserMixin):
    def __init__(self, id, username, password, role):
        self.id = id
        self.username = username
        self.password = password
        self.role = role

# In-memory user storage
users = {
    'admin': User('1', 'admin', 'admin', 'admin'),
    'user': User('2', 'user', 'user', 'user')
}

@login_manager.user_loader
def load_user(user_id):
    return next((user for user in users.values() if user.id == user_id), None)

# Routes
@app.route('/')
def index():
    return 'Home Page'

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = users.get(username)
        if user and user.password == password:
            login_user(user)
            identity_changed.send(current_app._get_current_object(), identity=Identity(user.id))
            return redirect(url_for('index'))
        else:
            flash('Invalid credentials')
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    identity_changed.send(current_app._get_current_object(), identity=AnonymousIdentity())
    return redirect(url_for('index'))

@app.route('/admin')
@login_required
@admin_permission.require(http_exception=403)
def admin():
    return 'Admin Page'

@app.route('/user')
@login_required
@user_permission.require(http_exception=403)
def user():
    return 'User Page'

@app.errorhandler(403)
def forbidden(e):
    return 'Access Forbidden', 403

@identity_loaded.connect_via(app)
def on_identity_loaded(sender, identity):
    identity.user = current_user
    if hasattr(current_user, 'role'):
        identity.provides.add(RoleNeed(current_user.role))

if __name__ == '__main__':
    app.run(debug=True)
