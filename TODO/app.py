import os
from datetime import datetime, date, timedelta
from flask import Flask, render_template, redirect, url_for, flash, request, abort
from flask_sqlalchemy import SQLAlchemy
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField, TextAreaField, BooleanField, SelectField
from wtforms.fields import DateField # Correct import for DateField
from wtforms.validators import DataRequired, Email, EqualTo, Length, Optional
from flask_login import LoginManager, UserMixin, login_user, logout_user, current_user, login_required
from werkzeug.security import generate_password_hash, check_password_hash
from sqlalchemy import func # For db.func.date

from flask_wtf.csrf import generate_csrf

# --- Configuration ---
BASE_DIR = os.path.abspath(os.path.dirname(__file__))

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your_very_secret_key_here' # Change this!
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///' + os.path.join(BASE_DIR, 'todo_app.db')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# --- Extensions ---
db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login' # Route name for login page
login_manager.login_message_category = 'info'

# --- Models ---
class User(UserMixin, db.Model):
    __tablename__ = 'user'
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(200), nullable=False)
    todos = db.relationship('Todo', backref='author', lazy='dynamic', cascade="all, delete-orphan")
    notifications = db.relationship('Notification', foreign_keys='Notification.user_id', backref='recipient', lazy='dynamic', cascade="all, delete-orphan")

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

    def __repr__(self):
        return f'<User {self.username}>'

class Todo(db.Model):
    __tablename__ = 'todo'
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(150), nullable=False)
    description = db.Column(db.Text, nullable=True)
    due_date = db.Column(db.DateTime, nullable=True)
    is_completed = db.Column(db.Boolean, default=False, nullable=False)
    priority = db.Column(db.String(20), default='Medium') # 'High', 'Medium', 'Low'
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow, nullable=False)
    notifications = db.relationship('Notification', foreign_keys='Notification.todo_id', backref='related_task', lazy='dynamic', cascade="all, delete-orphan")


    def __repr__(self):
        return f'<Todo {self.title}>'

class Notification(db.Model):
    __tablename__ = 'notification'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    todo_id = db.Column(db.Integer, db.ForeignKey('todo.id'), nullable=True)
    message = db.Column(db.String(255), nullable=False)
    is_read = db.Column(db.Boolean, default=False, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    notification_type = db.Column(db.String(50), default='general')

    def __repr__(self):
        return f"<Notification {self.id} for User {self.user_id} - Read: {self.is_read}>"

# --- Forms ---
class RegistrationForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired(), Length(min=4, max=80)])
    email = StringField('Email', validators=[DataRequired(), Email(), Length(max=120)])
    password = PasswordField('Password', validators=[DataRequired(), Length(min=6)])
    confirm_password = PasswordField('Confirm Password', validators=[DataRequired(), EqualTo('password')])
    submit = SubmitField('Register')

    def validate_username(self, username):
        user = User.query.filter_by(username=username.data).first()
        if user:
            raise ValueError('That username is already taken. Please choose a different one.')

    def validate_email(self, email):
        user = User.query.filter_by(email=email.data).first()
        if user:
            raise ValueError('That email is already registered. Please use a different one or login.')

class LoginForm(FlaskForm):
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired()])
    remember = BooleanField('Remember Me')
    submit = SubmitField('Login')

class TodoForm(FlaskForm):
    title = StringField('Title', validators=[DataRequired(), Length(max=150)])
    description = TextAreaField('Description', validators=[Optional(), Length(max=500)])
    due_date = DateField('Due Date (YYYY-MM-DD)', format='%Y-%m-%d', validators=[Optional()])
    priority = SelectField('Priority', choices=[('High', 'High'), ('Medium', 'Medium'), ('Low', 'Low')], default='Medium')
    submit = SubmitField('Add Todo')

class EditTodoForm(TodoForm): # Inherits from TodoForm
    submit = SubmitField('Update Todo')


# --- User Loader ---
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# --- Helper: Create Due Today Notifications ---
def create_due_today_notifications(user):
    today = date.today()
    # Todos due today, not completed, for the given user
    current_todos_for_notification = Todo.query.filter(
        Todo.user_id == user.id,
        Todo.is_completed == False,
        Todo.due_date.isnot(None), # Ensure due_date is set
        func.date(Todo.due_date) == today # Compare only the date part
    ).all()

    notifications_created_count = 0
    for todo_item in current_todos_for_notification:
        # Check if a 'due_today' notification for this task on this day already exists
        existing_notification = Notification.query.filter(
            Notification.user_id == user.id,
            Notification.todo_id == todo_item.id,
            Notification.notification_type == 'due_today',
            func.date(Notification.created_at) == today
        ).first()

        if not existing_notification:
            new_notif = Notification(
                user_id=user.id,
                todo_id=todo_item.id,
                message=f"Reminder: Task '{todo_item.title}' is due today!",
                notification_type='due_today'
            )
            db.session.add(new_notif)
            notifications_created_count += 1
    if notifications_created_count > 0:
        db.session.commit()


# --- Routes ---
@app.route('/')
@app.route('/dashboard')
@login_required
def dashboard():
    # Create notifications for tasks due today when user visits dashboard
    create_due_today_notifications(current_user)

    pending_tasks_count = Todo.query.filter_by(user_id=current_user.id, is_completed=False).count()
    # Example: get a few urgent tasks for the dashboard
    urgent_tasks = Todo.query.filter(
        Todo.user_id == current_user.id,
        Todo.is_completed == False,
        Todo.due_date.isnot(None) # Has a due date
    ).order_by(Todo.due_date.asc()).limit(5).all()

    return render_template('dashboard.html',
                           title='Dashboard',
                           pending_tasks_count=pending_tasks_count,
                           urgent_tasks=urgent_tasks)

@app.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    form = RegistrationForm()
    if form.validate_on_submit():
        try:
            user = User(username=form.username.data, email=form.email.data)
            user.set_password(form.password.data)
            db.session.add(user)
            db.session.commit()
            flash('Your account has been created! You are now able to log in.', 'success')
            login_user(user) # Optionally log them in directly
            return redirect(url_for('dashboard'))
        except ValueError as e:
            flash(str(e), 'danger')
        except Exception as e:
            db.session.rollback()
            flash(f'An error occurred: {e}', 'danger')
    return render_template('register.html', title='Register', form=form)

@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        if user and user.check_password(form.password.data):
            login_user(user, remember=form.remember.data)
            next_page = request.args.get('next')
            flash('Login successful!', 'success')
            return redirect(next_page) if next_page else redirect(url_for('dashboard'))
        else:
            flash('Login Unsuccessful. Please check email and password.', 'danger')
    return render_template('login.html', title='Login', form=form)

@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('You have been logged out.', 'info')
    return redirect(url_for('login'))

@app.route('/todos/add', methods=['GET', 'POST'])
@login_required
def add_todo():
    form = TodoForm()
    if form.validate_on_submit():
        due_date_val = form.due_date.data if form.due_date.data else None
        todo = Todo(
            title=form.title.data,
            description=form.description.data,
            due_date=due_date_val,
            priority=form.priority.data,
            author=current_user
        )
        db.session.add(todo)
        db.session.commit()
        flash('Your To-Do has been created!', 'success')
        return redirect(url_for('view_todos'))
    return render_template('add_todo.html', title='Add To-Do', form=form, legend='New To-Do')

@app.route('/todos')
@login_required
def view_todos():
    today = date.today()
    tomorrow = today + timedelta(days=1)

    create_due_today_notifications(current_user)

    # For debugging: print current user ID
    print(f"--- Checking todos for user ID: {current_user.id} ---")

    pending_todos_list = Todo.query.filter(
        Todo.user_id == current_user.id,
        Todo.is_completed == False,
        Todo.due_date.isnot(None),
        Todo.due_date < datetime.combine(today, datetime.min.time())
    ).order_by(Todo.due_date.asc()).all()
    print(f"Pending Todos: {pending_todos_list}") # See if this list is empty or has items

    current_todos_list = Todo.query.filter(
        Todo.user_id == current_user.id,
        Todo.is_completed == False,
        Todo.due_date.isnot(None),
        func.date(Todo.due_date) == today
    ).order_by(Todo.priority, Todo.due_date.asc()).all()
    print(f"Current Todos: {current_todos_list}")

    upcoming_todos_list = Todo.query.filter(
        Todo.user_id == current_user.id,
        Todo.is_completed == False,
        Todo.due_date.isnot(None),
        Todo.due_date >= datetime.combine(tomorrow, datetime.min.time())
    ).order_by(Todo.due_date.asc()).all()
    print(f"Upcoming Todos: {upcoming_todos_list}")

    no_due_date_todos_list = Todo.query.filter(
        Todo.user_id == current_user.id,
        Todo.is_completed == False,
        Todo.due_date.is_(None)
    ).order_by(Todo.created_at.desc()).all()
    print(f"No Due Date Todos: {no_due_date_todos_list}")

    completed_todos_list = Todo.query.filter_by(
        user_id=current_user.id, is_completed=True
    ).order_by(Todo.updated_at.desc()).all()
    print(f"Completed Todos: {completed_todos_list}")

    todo_sections_data = {
        'pending_todos': pending_todos_list,
        'current_todos': current_todos_list,
        'upcoming_todos': upcoming_todos_list,
        'no_due_date_todos': no_due_date_todos_list,
        'completed_todos': completed_todos_list
    }

    csrf_token_val = ''
    try:
        csrf_token_val = generate_csrf()
    except RuntimeError:
        app.logger.warning("Could not generate CSRF token for view_todos. Ensure CSRF is configured.")
        pass

    return render_template('view_todos.html',
                           title='View To-Dos',
                           todo_sections=todo_sections_data,
                           csrf_token_value=csrf_token_val,
                           now=datetime.utcnow
                           )
@app.route('/todo/<int:todo_id>/complete', methods=['POST']) 
@login_required
def complete_todo(todo_id):
    todo = Todo.query.get_or_404(todo_id)
    if todo.author != current_user:
        abort(403) # Forbidden
    todo.is_completed = True
    todo.updated_at = datetime.utcnow() # Manually set if onupdate not reliable
    db.session.commit()
    flash('To-Do marked as completed!', 'success')
    return redirect(url_for('view_todos'))

@app.route('/todo/<int:todo_id>/uncomplete', methods=['POST'])
@login_required
def uncomplete_todo(todo_id):
    todo = Todo.query.get_or_404(todo_id)
    if todo.author != current_user:
        abort(403)
    todo.is_completed = False
    todo.updated_at = datetime.utcnow()
    db.session.commit()
    flash('To-Do marked as not completed.', 'info')
    return redirect(url_for('view_todos'))


@app.route('/todo/<int:todo_id>/delete', methods=['POST'])
@login_required
def delete_todo(todo_id):
    todo = Todo.query.get_or_404(todo_id)
    if todo.author != current_user:
        abort(403)
    # Delete related notifications first if cascade isn't working as expected or for explicit control
    Notification.query.filter_by(todo_id=todo.id).delete()
    db.session.delete(todo)
    db.session.commit()
    flash('To-Do has been deleted!', 'success')
    return redirect(url_for('view_todos'))

@app.route('/todo/<int:todo_id>/edit', methods=['GET', 'POST'])
@login_required
def edit_todo(todo_id):
    todo = Todo.query.get_or_404(todo_id)
    if todo.author != current_user:
        abort(403)
    form = EditTodoForm(obj=todo) # Pre-populate form with todo data
    if form.validate_on_submit():
        todo.title = form.title.data
        todo.description = form.description.data
        todo.due_date = form.due_date.data if form.due_date.data else None
        todo.priority = form.priority.data
        todo.updated_at = datetime.utcnow()
        db.session.commit()
        flash('Your To-Do has been updated!', 'success')
        return redirect(url_for('view_todos'))
    elif request.method == 'GET':
        # This will pre-fill the form when it's first loaded
        form.title.data = todo.title
        form.description.data = todo.description
        form.due_date.data = todo.due_date.date() if todo.due_date else None # Make sure to pass date object if field expects it
        form.priority.data = todo.priority
    return render_template('add_todo.html', title='Edit To-Do', form=form, legend=f'Edit To-Do: "{todo.title}"', todo=todo)


@app.route('/notifications')
@login_required
def notifications_page():
    # Ensure due today notifications are fresh
    create_due_today_notifications(current_user)

    user_notifications = Notification.query.filter_by(user_id=current_user.id)\
                                       .order_by(Notification.is_read.asc(), Notification.created_at.desc()).all()
    unread_count = Notification.query.filter_by(user_id=current_user.id, is_read=False).count()

    return render_template('notifications.html',
                           title='Notifications',
                           notifications=user_notifications,
                           unread_count=unread_count)

@app.route('/notifications/mark_read/<int:notification_id>', methods=['POST'])
@login_required
def mark_notification_read(notification_id):
    notification = Notification.query.get_or_404(notification_id)
    if notification.recipient != current_user:
        abort(403)
    notification.is_read = True
    db.session.commit()
    flash('Notification marked as read.', 'success')
    return redirect(request.referrer or url_for('notifications_page'))


@app.route('/notifications/mark_all_read', methods=['POST'])
@login_required
def mark_all_notifications_read():
    notifications_to_mark = Notification.query.filter_by(user_id=current_user.id, is_read=False).all()
    for notif in notifications_to_mark:
        notif.is_read = True
    if notifications_to_mark: # Only commit if there was something to change
        db.session.commit()
        flash('All unread notifications marked as read.', 'success')
    else:
        flash('No unread notifications to mark.', 'info')
    return redirect(url_for('notifications_page'))

# --- Context Processors (to make variables available in all templates) ---
@app.context_processor
def inject_unread_notification_count():
    if current_user.is_authenticated:
        count = Notification.query.filter_by(user_id=current_user.id, is_read=False).count()
        return dict(unread_notifications_count=count)
    return dict(unread_notifications_count=0)

if __name__ == '__main__':
    app.run(debug=True)