from flask import *
from flask_sqlalchemy import SQLAlchemy
from datetime import timedelta


db = SQLAlchemy()

app = Flask(__name__, template_folder="templates")

# database configuration
app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///users.sqlite3"
db.init_app(app)

# session configuration
app.permanent_session_lifetime = timedelta(days=2)
app.secret_key = "secretkey"

# database models
class Users(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(30), unique=True)
    password = db.Column(db.String(50))
    email = db.Column(db.String(254), unique=True)

    def __init__(self, username, password, email):
        self.username = username
        self.password = password
        self.email = email

class Tasks(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id"))
    content = db.Column(db.String(100))

    def __init__(self, user_id, content):
        self.user_id = user_id
        self.content = content

def retrieve_tasks():
    task_list = []
    for task in db.engine.execute(f"SELECT tasks.content, tasks.id FROM tasks INNER JOIN users ON users.id = tasks.user_id WHERE tasks.user_id = '{session['user_id']}'").all():
        task_list.append((task[0], task[1]))  # each task has its content (task[0]) and its id in the tasks table (task[1])
    return task_list

# function that checks if a session is active
def is_session_active():
    if session.get("username") == None:
        return False
    return True


def is_task_content_valid(task_content):
    if len(task_content) == 0:
        return False

    # only validate the task if it contains digits or/and lower letters or/and upper letters
    for c in task_content:
        if c.islower() == False and c.isupper() == False and c.isdigit() == False and c != " ":
            return False
    return True

@app.route("/", methods=["GET", "POST"])
def home():
    
    # if the user is logged in, we render the app page
    if is_session_active():

        # refresh the list of tasks
        session["task_list"] = retrieve_tasks()
    
        if request.method == "POST":

            if "task_submit_btn" in request.form:

                task = request.form["task"]
                
                # only add the content to the database if the task is valid
                if is_task_content_valid(task) == True:
                    db.engine.execute(f"INSERT INTO tasks(user_id, content) VALUES('{session['user_id']}', '{task}')")
                    session["task_list"] = retrieve_tasks()  #refresh after inserting the value
                else:
                    flash("Please enter a valid task", "error")
            
        return render_template("index.html", task_list=session["task_list"], is_session_active=True)

    # else we redirect him to the signin or signup page
    else:
        return redirect(url_for("not_logged_in"))

@app.route("/not-logged-in")
def not_logged_in():
    
    # only render this page if user is not logged in
    if is_session_active() == False:
        return render_template("not_logged_in.html",is_session_active=False)
    
    # else we redirect him to the app page
    else:
        return redirect(url_for("home"))


def is_password_valid(password: str):

    # first check if the length is valid
    if len(password) > 30 or len(password) < 8:
        return False
    
    is_there_lower = False
    is_there_upper = False
    is_there_digit = False
    #is_there_special_character = False

    # second iterate through all the characters and check the characters types
    for c in password:

        if c.islower():
            is_there_lower = True
        elif c.isupper():
            is_there_upper = True
        elif c.isdigit():
            is_there_digit = True

        if ord(c) > 127 or ord(c) < 32:
            return False

    # then check if the conditions are correct
    if is_there_lower and is_there_upper and is_there_digit:
        return True
    else:
        return False


def is_username_valid(username: str):
    if len(username) > 30 or len(username) < 6:
        return False

    forbidden_characters = "&=\"#%&\'()*+,-./:;<=>?@[\]`{|}~"
    for c in username:

        # check if character is a forbidden character
        for forbidden_character in forbidden_characters:
            if c == forbidden_character:
                return False
        # check if the character is in the ascii table
        # or if it is below 33
        if ord(c) > 127 or ord(c)< 33:
            return False

    return True


def is_email_valid(email : str):
    if len(email) > 254 or len(email) < 5:
        return False
    
    ### if the first character is @ or .  or the last character is @ or .  the email is invalid
    if email[0] == "@" or email[0] == "." or email[len(email)-1] == "@" or email[len(email)-1] == ".":
        return False

    forbidden_characters = "&=\"#%&\'()*+,/:;<=>?[\]`{|}~"

    is_there_at_symbol = False               # bool variable for checking if there is already a @ symbol
    is_there_dot_after_at_symbol = False     # check if there is a . after the @

    # iterate through email with index for the double . checking
    for c in range(len(email)):

        if is_there_at_symbol == True:
            if email[c] == ".":
                if is_there_dot_after_at_symbol == False:
                    is_there_dot_after_at_symbol = True
                # if is_there_dot_after_at_symbol is true, it is because there was already a . before, so the email is invalid
                else:
                    return False

        if email[c] == "@":
            if is_there_at_symbol == False:
                is_there_at_symbol = True
            # if is_there_at_symbol is true, it is because there was already a @ before, so the email is invalid
            else:
                return False

        ### check if the current character is a forbidden character
        for forbidden_character in forbidden_characters:
            if email[c] == forbidden_character:
                return False

        if ord(email[c]) > 127 or ord(email[c])< 33:
            return False

        # if there is two consecutive . appearance 
        # or if there is .@ consecutively
        # of if there is @. consecutively
        # then the email is invalid
        if (email[c] == "." and email[c-1] == ".") or (email[c-1] == "." and email[c] == "@") or (email[c-1] == "@" and email[c] == "."):
            return False

    if is_there_at_symbol and is_there_dot_after_at_symbol:
        return True
    else:
        return False

@app.route("/register", methods=["GET", "POST"])
def register():

    if request.method == "POST":
        
        username = request.form.get("username-register")
        password = request.form.get("password-register")
        email = request.form.get("email-register")

        if is_username_valid(username) and is_password_valid(password) and is_email_valid(email):

            user_exists = db.engine.execute(f"SELECT EXISTS(SELECT * FROM users WHERE username = '{username}')").one()[0];   # one() is to get the only resulting row and [0] because the row is returned as a tuple
            email_exists = db.engine.execute(f"SELECT EXISTS(SELECT * FROM users WHERE email = '{email}')").one()[0];

            # register the user if he doesn't already exists
            if user_exists == False and email_exists == False:
                db.engine.execute(f"INSERT INTO users(username, password, email) VALUES('{username}', '{password}', '{email}')")
            
                session["username"] = username
                session["email"] = email
                session["user_id"] = db.engine.execute(f"SELECT id FROM users WHERE username='{username}'").one()[0]

                session["task_list"] = retrieve_tasks()

                flash("Successfully registered", "success")

                return redirect(url_for("home"))
            else:
                if user_exists:
                    flash("Unable to register, this username is already used", "error")
                elif email_exists:
                    flash("Unable to register, this email is already used", "error")
        
        else:
            if is_username_valid(username) == False:
                flash("Invalid username, it must contains at least 6 characters", "error")
            elif is_password_valid(password) == False:
                flash("Invalid password, it must contains at least a lowercase letter, an uppercase letter and a digit", "error")
            elif is_email_valid(email) == False:
                flash("Invalid email", "error")

    return render_template("register.html", is_session_active=is_session_active())


@app.route("/login", methods=["GET", "POST"])
def login():

    if request.method == "POST":
        username = request.form.get("username-login")
        password = request.form.get("password-login")

        # first check if all the caracteristics of a username and password are correct 
        if is_username_valid(username) == False or is_password_valid(password) == False:
            flash("Incorrect username and/or password", "error")
        # if it is the case, we can verify if the informations are in the database
        else:
            user_exists = db.engine.execute(f"SELECT EXISTS(SELECT * FROM users WHERE username = '{username}')").one()[0]
            # is the user exists, we verify if the password corresponds
            if user_exists:
                # get the password of the corresponding user
                user_password = db.engine.execute(f"SELECT password FROM users WHERE username='{username}'").one()[0]

                # if the entered password is the right password, we log in
                if user_password == password:

                    session["username"] = username
                    session["email"] = db.engine.execute(f"SELECT email FROM users WHERE username='{username}'").one()[0]
                    session["user_id"] = db.engine.execute(f"SELECT id FROM users WHERE username='{username}'").one()[0]

                    ## retrieve the tasks from the database
                    session["task_list"] = retrieve_tasks()

                    flash("Successfully logged in", "success")
                    return redirect(url_for("home"))

            flash("Incorrect username and/or password", "error")


    return render_template("login.html", is_session_active=is_session_active())

@app.route("/forgot-password")
def forgot_password():
    return render_template("forgot_password.html", is_session_active=is_session_active())

@app.route("/logout")
def logout():
    # only logout if there is an active session
    if is_session_active():
        session["username"] = None
        session["email"] = None
        session["user_id"] = None
        session["task_list"] = None
        flash("Successfully logged out", "success")
        return redirect(url_for("not_logged_in"))

@app.route("/functions/edit-task-id=<task_id>")
def edit_task(task_id):
    flash("Can't edit a task right now", "info")
    return redirect(url_for("home"))


# url that works as a function
@app.route("/functions/delete-task-id=<task_id>")
def delete_task(task_id):
    #### only delete if the user that deletes the task is the logged in user

    # retrieve user id from the corresponding task id
    task_user_id = db.engine.execute(f"SELECT user_id FROM tasks WHERE id={task_id}").one()[0]

    # if the task user id corresponds to the logged in user id, we delete the task 
    if task_user_id == session["user_id"]:
        db.engine.execute(f"DELETE FROM tasks WHERE id={task_id}")
    # else we don't delete the task
    else:
        flash("You can only delete your tasks", "error")

    return redirect(url_for("home"))

@app.errorhandler(404)
def error_page_not_found(error):
    return render_template("error404.html", is_session_active=is_session_active())

if __name__ == "__main__":
    app.app_context().push() # needed for db creation
    db.create_all()
    app.run(debug=True)