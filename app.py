from flask import Flask, render_template, redirect, request, flash, url_for
from flask_bootstrap import Bootstrap
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, TextAreaField, SubmitField
from wtforms.validators import DataRequired, Email, EqualTo
from flask_login import LoginManager, UserMixin, login_user, logout_user, current_user, login_required
from werkzeug.security import generate_password_hash, check_password_hash
from flask_sqlalchemy import SQLAlchemy

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your-secret-key'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///blog.db'

bootstrap = Bootstrap(app)
db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'


# User model
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), unique=True)
    email = db.Column(db.String(50), unique=True)
    password_hash = db.Column(db.String(100))
    blogs = db.relationship('Blog', backref='author', lazy=True)


# Blog model
class Blog(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(100))
    content = db.Column(db.Text)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))


# Create tables
with app.app_context():
    db.create_all()


# Login manager
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


# Forms
class LoginForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired()])
    submit = SubmitField('Log In')


class SignupForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired()])
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired()])
    confirm_password = PasswordField('Confirm Password',
                                     validators=[DataRequired(), EqualTo('password')])
    submit = SubmitField('Sign Up')


class BlogForm(FlaskForm):
    title = StringField('Title', validators=[DataRequired()])
    content = TextAreaField('Content', validators=[DataRequired()])
    submit = SubmitField('Save')


# Routes
@app.route('/')
def home():
    blogs = Blog.query.all()
    return render_template('index.html', blogs=blogs)


@app.route('/signup', methods=['GET', 'POST'])
def signup():
    form = SignupForm()
    if form.validate_on_submit():
        existing_user = User.query.filter_by(username=form.username.data).first()
        if existing_user:
            flash('Username already exists. Please choose a different one.', 'danger')
        else:
            password_hash = generate_password_hash(form.password.data)
            user = User(username=form.username.data, email=form.email.data, password_hash=password_hash)
            db.session.add(user)
            db.session.commit()
            flash('Account created successfully. You can now log in.', 'success')
            return redirect(url_for('login'))
    return render_template('signup.html', form=form)


@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user and check_password_hash(user.password_hash, form.password.data):
            login_user(user)
            return redirect(url_for('home'))
        else:
            flash('Invalid username or password.', 'danger')
    return render_template('login.html', form=form)


@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('home'))


@app.route('/blog/<int:blog_id>')
def full_blog(blog_id):
    blog = Blog.query.get_or_404(blog_id)
    return render_template('full_blog.html', blog=blog)



@app.route('/blog/create', methods=['GET', 'POST'])
@login_required
def create_blog():
    form = BlogForm()
    if form.validate_on_submit():
        blog = Blog(title=form.title.data, content=form.content.data, author=current_user)
        db.session.add(blog)
        db.session.commit()
        flash('Blog created successfully.', 'success')
        return redirect(url_for('home'))
    return render_template('create_blog.html', form=form)


@app.route('/blog/<int:blog_id>/edit', methods=['GET', 'POST'])
@login_required
def edit_blog(blog_id):
    blog = Blog.query.get_or_404(blog_id)
    if blog.author != current_user:
        flash('You are not authorized to edit this blog.', 'danger')
        return redirect(url_for('home'))
    form = BlogForm()
    if form.validate_on_submit():
        blog.title = form.title.data
        blog.content = form.content.data
        db.session.commit()
        flash('Blog updated successfully.', 'success')
        return redirect(url_for('home'))
    elif request.method == 'GET':
        form.title.data = blog.title
        form.content.data = blog.content
    return render_template('edit_blog.html', form=form, blog_id=blog_id)


@app.route('/blog/<int:blog_id>/delete', methods=['POST'])
@login_required
def delete_blog(blog_id):
    blog = Blog.query.get_or_404(blog_id)
    if blog.author != current_user:
        flash('You are not authorized to delete this blog.', 'danger')
        return redirect(url_for('home'))
    db.session.delete(blog)
    db.session.commit()
    flash('Blog deleted successfully.', 'success')
    return redirect(url_for('home'))


@app.route('/search', methods=['GET'])
def search_blogs():
    query = request.args.get('query', '')

    if query:
        blogs = Blog.query.filter(Blog.title.ilike(f'%{query}%') | Blog.content.ilike(f'%{query}%')).all()
    else:
        blogs = Blog.query.all()

    return render_template('index.html', blogs=blogs)



if __name__ == '__main__':
    app.run(debug=True)
