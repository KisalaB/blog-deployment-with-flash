from datetime import date
from flask import Flask, abort, render_template, redirect, url_for, flash, request
from flask_bootstrap import Bootstrap5
from flask_ckeditor import CKEditor, CKEditorField
from flask_login import UserMixin, login_user, LoginManager, current_user, logout_user, login_required
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.orm import relationship, DeclarativeBase, Mapped, mapped_column
from sqlalchemy import Integer, String, Text
from functools import wraps
from werkzeug.security import generate_password_hash, check_password_hash
from forms import CreatePostForm, RegisterForm, LoginForm, CommentForm

app = Flask(__name__)
app.config['SECRET_KEY'] = '8BYkEfBA6O6donzWlSihBXox7C0sKR6b'
ckeditor = CKEditor(app)
Bootstrap5(app)

login_manager = LoginManager(app)
login_manager.login_view = 'login'
login_manager.login_message = "Please log in to access this page."
login_manager.login_message_category = "warning"  # or 'info', 'success', etc.

@login_manager.user_loader
def load_user(user_id):
    return db.session.get(User, int(user_id))

# CREATE DATABASE
class Base(DeclarativeBase):
    pass
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///posts.db'
db = SQLAlchemy(model_class=Base)
db.init_app(app)


# CONFIGURE TABLES
class User(UserMixin, db.Model):
    __tablename__ = "user"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    email: Mapped[str] = mapped_column(String(100), unique=True)
    password: Mapped[str] = mapped_column(String(100))
    name: Mapped[str] = mapped_column(String(1000))
    is_admin: Mapped[bool] = mapped_column(String(100))
    posts: Mapped[list["BlogPost"]] = relationship("BlogPost", back_populates="author", cascade="all, delete")
    comments: Mapped[list["Comment"]] = relationship("Comment", back_populates="author", cascade="all, delete")


class BlogPost(db.Model):
    __tablename__ = "blog_posts"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    title: Mapped[str] = mapped_column(String(250), unique=True, nullable=False)
    subtitle: Mapped[str] = mapped_column(String(250), nullable=False)
    date: Mapped[str] = mapped_column(String(250), nullable=False)
    body: Mapped[str] = mapped_column(Text, nullable=False)
    author_id: Mapped[int] = mapped_column(Integer, db.ForeignKey('user.id'), nullable=False)
    img_url: Mapped[str] = mapped_column(String(250), nullable=False)
    author: Mapped["User"] = relationship("User", back_populates="posts")
    comments: Mapped[list["Comment"]] = relationship("Comment", back_populates="post", cascade="all, delete")


class Comment(db.Model):
    __tablename__ = "comments"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    comment: Mapped[str] = mapped_column(Text, nullable=False)
    post_id: Mapped[int] = mapped_column(Integer, db.ForeignKey('blog_posts.id'), nullable=False)
    author_id: Mapped[int] = mapped_column(Integer, db.ForeignKey('user.id'), nullable=False)
    post: Mapped["BlogPost"] = relationship("BlogPost", back_populates="comments")
    author: Mapped["User"] = relationship("User", back_populates="comments")


with app.app_context():
    db.create_all()

def admin_only(func):
    @wraps(func)
    def decorated_function(*args, **kwargs):
        if bool(int(current_user.is_admin)):
            return func(*args, **kwargs)
        else:
            flash("Sorry, you do not have permission to perform that function", "danger")
            return redirect(url_for("get_all_posts"))
    return decorated_function

@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegisterForm()
    if form.validate_on_submit():
        name = form.username.data
        email = form.email.data
        password = generate_password_hash(form.password.data,method='scrypt', salt_length=16)
        if User.query.filter_by(email=email).first():
            flash("You've already registered with that email. Login instead", 'danger')
            return redirect(url_for('login'))
        with app.app_context():
            user = User()
            user.name = name
            user.email = email
            user.password = password
            user.is_admin = (True if email == "jameskisala@gmail.com" else False)
            db.session.add(user)
            db.session.commit()
            flash('Account created successfully!', 'success')
            login_user(user)
            return redirect(url_for('get_all_posts', name=name))
    return render_template("register.html", form=form)


@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        email = form.email.data
        password = form.password.data
        user = User.query.filter_by(email=email).first()
        password_hash = user.password
        if user and check_password_hash(user.password, password):
            login_user(user)
            return redirect(url_for('get_all_posts', name=user.name))
        else:
            flash('Login Unsuccessful. Please check email and password', 'danger')
    return render_template("login.html", form=form)


@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('get_all_posts'))


@app.route('/')
def get_all_posts():
    result = db.session.execute(db.select(BlogPost))
    posts = result.scalars().all()
    return render_template("index.html", all_posts=posts)


# TODO: Allow logged-in users to comment on posts
@app.route("/post/<int:post_id>", methods=["GET", "POST"])
def show_post(post_id):
    form = CommentForm()
    if form.validate_on_submit():
        if current_user.is_authenticated:
            with app.app_context():
                user = Comment()
                user.comment = form.body.data
                user.post_id = post_id
                user.author_id = current_user.id
                db.session.add(user)
                db.session.commit()
                return redirect(url_for("show_post", post_id=post_id))
        else:
            flash("You must be logged in to comment", "danger")
            return redirect(url_for("login"))

    requested_post = db.get_or_404(BlogPost, post_id)
    # print(requested_post.comments[0].author.name)
    # print(requested_post.comments[0].comment)
    return render_template("post.html", post=requested_post, comment=form, comments=requested_post.comments)


@app.route("/new-post", methods=["GET", "POST"])
@admin_only
def add_new_post():
    form = CreatePostForm()
    if form.validate_on_submit():
        new_post = BlogPost(
            title=form.title.data,
            subtitle=form.subtitle.data,
            body=form.body.data,
            img_url=form.img_url.data,
            author=current_user,
            date=date.today().strftime("%B %d, %Y")
        )
        db.session.add(new_post)
        db.session.commit()
        return redirect(url_for("get_all_posts"))
    return render_template("make-post.html", form=form)


@app.route("/edit-post/<int:post_id>", methods=["GET", "POST"])
@admin_only
def edit_post(post_id):
    post = db.get_or_404(BlogPost, post_id)
    edit_form = CreatePostForm(
        title=post.title,
        subtitle=post.subtitle,
        img_url=post.img_url,
        author=post.author,
        body=post.body
    )
    if edit_form.validate_on_submit():
        post.title = edit_form.title.data
        post.subtitle = edit_form.subtitle.data
        post.img_url = edit_form.img_url.data
        post.author = current_user
        post.body = edit_form.body.data
        db.session.commit()
        return redirect(url_for("get_all_posts", post_id=post.id))
    return render_template("make-post.html", form=edit_form, is_edit=True)


@app.route("/delete/<int:post_id>")
@admin_only
def delete_post(post_id):
    post_to_delete = db.get_or_404(BlogPost, post_id)
    db.session.delete(post_to_delete)
    db.session.commit()
    return redirect(url_for('get_all_posts'))


@app.route("/about")
def about():
    return render_template("about.html")


@app.route("/contact")
def contact():
    return render_template("contact.html")


if __name__ == "__main__":
    app.run(debug=True, port=5002)
