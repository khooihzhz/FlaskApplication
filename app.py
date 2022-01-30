from flask import Flask, render_template, request, flash, session, redirect, url_for, jsonify
import requests
from flask_restful import Api, Resource
import sqlite3
import os
from dotenv import load_dotenv
from flask_bcrypt import Bcrypt

# get environment variable
load_dotenv()
app = Flask(__name__)
app.secret_key = os.getenv("SECRET_KEY")
api = Api(app)
bcrypt = Bcrypt(app)


# ------------------API---------------------

# ---------Helper Functions------------
# get password hash
def get_password_hash(password):
    return bcrypt.generate_password_hash(password).decode('utf-8')


# verify password hash
def verify_password_hash(password, hashed_password):
    return bcrypt.check_password_hash(hashed_password, password)


# custom 404 page
@app.errorhandler(404)
def page_not_found(e):
    # note that we set the 404 status explicitly
    return render_template('404.html'), 404


# .....Login.....
class Login(Resource):
    # noinspection PyMethodMayBeStatic
    def post(self):
        # get data from post request
        data = request.get_json()
        # get username and password from data
        if data["roles"] == "admin":
            username = data["username"]
            password = data["password"]
            # connect to database
            conn = sqlite3.connect("employee_info_db")
            conn.row_factory = sqlite3.Row
            # create cursor
            c = conn.cursor()
            # get user by username
            result = c.execute("SELECT * FROM admin_auth WHERE username = ?", (username,))
            if result.fetchone() is None:
                return {"message": "username not found"}, 404
            result = c.execute("SELECT * FROM admin_auth WHERE username = ?", (username,))
            result = dict(result.fetchone())
            # verify password
            if password == result["password"]:
                # return success
                return {"message": "Login Success"}, 200
            else:
                # return failure
                return {"message": "Login Failed"}, 404
        else:
            username = data["username"]
            password = data["password"]
            # connect to database
            conn = sqlite3.connect("employee_info_db")
            conn.row_factory = sqlite3.Row
            # create cursor
            c = conn.cursor()
            # get user by username
            result = c.execute("SELECT * FROM employee_info WHERE username = ?", (username,))
            # get stored hash
            results = dict(result.fetchone())
            hashed_password = results['password']
            # verify password
            if verify_password_hash(password, hashed_password):
                # return success
                return {"message": "Login Success", "employee_id": results["employee_id"]}, 200
            else:
                # return failure
                return {"message": "Login Failed"}, 404


# ..... Register / Create User.....
class Register(Resource):
    # noinspection PyMethodMayBeStatic
    def post(self):
        # get data from post request
        # catch key error
        try:
            data = request.get_json()
            employee_name = data['employee_name']
            email = data['email']
            address = data['address']
            gender = data['gender']
            education = data['education']
            username = data['username']
            password = get_password_hash(data['password'])
        except KeyError:
            # key field invalid
            return {"message": "Invalid Key Field"}, 422
        # connect to database
        conn = sqlite3.connect("employee_info_db")
        # create cursor
        c = conn.cursor()
        # check if user exists
        result = c.execute("SELECT * FROM employee_info WHERE username = ?", (username,))
        if result.fetchone() is not None:
            return {"message": "User already exists"}, 409
        # insert user into database
        try:
            c.execute('INSERT INTO employee_info('
                      'employee_name, gender, email, address, academic_qualification, username, password) '
                      'VALUES (?, ?, ?, ?, ?, ?, ?)',
                      (employee_name, gender, email, address, education, username, password))
        # error inserting into db
        except sqlite3.Error as e:
            return {'message': 'Error registering user'}, 422
        # commit database
        conn.commit()
        return {'message': 'User Created'}, 201


# .....Employee Methods.....
class Employee(Resource):
    # noinspection PyMethodMayBeStatic
    # get employee with employee_id
    def get(self, employee_id):
        # connect to database
        conn = sqlite3.connect("employee_info_db")
        conn.row_factory = sqlite3.Row
        # create cursor
        c = conn.cursor()
        # get employee by id
        result = c.execute("SELECT * FROM employee_info WHERE employee_id = ?", (employee_id,))
        # employee does not exist
        if result.fetchone() is None:
            return {"message": "Employee does not exist"}, 404
        result = c.execute("SELECT * FROM employee_info WHERE employee_id = ?", (employee_id,))
        # employee (in a list) for easier
        employees = [dict(result.fetchone())]
        # return employees
        return jsonify({"htmlResponse": render_template("admins/employee_card.html",
                                                        employees=employees),
                        "employee": employees[0]})

    # noinspection PyMethodMayBeStatic
    # update employee with employee_id
    def put(self, employee_id):
        # get data from post request
        data = request.get_json()
        employee_name = data['employee_name']
        email = data['email']
        address = data['address']
        education = data['education']
        gender = data['gender']
        password = get_password_hash(data['password'])
        # connect to database
        conn = sqlite3.connect("employee_info_db")
        # create cursor
        c = conn.cursor()
        # update employee
        c.execute('UPDATE employee_info SET employee_name = ?, email = ?, address = ?, '
                  'academic_qualification = ?, gender = ?, password = ? WHERE employee_id = ?',
                  (employee_name, email, address, education, gender, password, employee_id))
        # commit database
        conn.commit()
        return {'message': 'User Updated'}, 200

    # delete employee with employee_id (ONLY ADMIN)
    # noinspection PyMethodMayBeStatic
    def delete(self, employee_id):
        # connect to database
        conn = sqlite3.connect("employee_info_db")
        # create cursor
        c = conn.cursor()
        result = c.execute("SELECT * FROM employee_info WHERE employee_id = ?", (employee_id,))
        # employee does not exist
        if result.fetchone() is None:
            return {"message": "Employee does not exist"}, 404
        # delete employee
        c.execute('DELETE FROM employee_info WHERE employee_id = ?', (employee_id,))
        # commit database
        conn.commit()
        return {'message': 'User Deleted'}, 200


# .....Admin Methods.....
class Admin(Resource):
    # get all employees (ONLY ADMIN)
    # noinspection PyMethodMayBeStatic
    def get(self):
        # connect to database
        conn = sqlite3.connect("employee_info_db")
        conn.row_factory = sqlite3.Row
        # create cursor
        c = conn.cursor()
        # get all employees
        result = c.execute("SELECT * FROM employee_info")
        # employees
        rows = result.fetchall()
        employees = []
        # get a list of dictionary
        for row in rows:
            employees.append(dict(row))
        # return employees
        return jsonify({"htmlResponse": render_template("admins/employee_card.html",
                                                        employees=employees)})


# .....API resources.....
api.add_resource(Login, "/api/login")
api.add_resource(Register, "/api/register")
api.add_resource(Employee, "/api/employee/<int:employee_id>")
api.add_resource(Admin, "/api/admins")

# -------- Front End --------
# ..API URL..
api_url = os.getenv("API_URL")


# ....HomePage....
@app.route('/')
def index():
    # if user is logged in
    if 'roles' in session:
        # if user is admin
        if session['roles'] == 'admin':
            return redirect(url_for("admin_home"))
        # if user is employee
        else:
            return redirect(url_for("employee_home"))

    return render_template('index.html')


# .....Login Page.....
@app.route('/login', methods=["GET", "POST"])
def login_view():
    if request.method == "POST":
        roles = request.form.get("roles")
        username = request.form.get("username")
        password = request.form.get("password")
        # send post request to api
        response = requests.post(api_url + "/login", json={"roles": roles, "username": username, "password": password})

        if response.status_code == 200:
            # if roles is admins
            if roles == "admin":
                # Log in
                # set session
                session["username"] = username
                session["roles"] = roles
                flash('Welcome ' + session['roles'], "success")
                return redirect(url_for('admin_home'))
            else:
                # set session
                session["employee_id"] = response.json()["employee_id"]
                session["roles"] = roles
                return redirect(url_for('employee_home'))
        else:
            flash("Invalid username or password", 'danger')
            return render_template("login.html")
    else:
        if 'roles' in session:
            # if user is employee
            if session['roles'] == 'employee':
                return redirect(url_for('employee_home'))
            # if user is admin
            if session['roles'] == 'admin':
                return redirect(url_for('admin_home'))
        return render_template("login.html")


# .....Register Page.....
@app.route('/register', methods=["GET", "POST"])
def register_view():
    # if user is logged in
    if 'roles' in session:
        # if user is employee
        if session['roles'] == 'employee':
            return redirect(url_for('employee_home'))
        # if user is admin
        if session['roles'] == 'admin':
            return redirect(url_for('admin_home'))

    if request.method == "POST":
        # get form data
        employee_name = request.form.get("employee_name")
        email = request.form.get("email")
        address = request.form.get("address")
        gender = request.form.get("gender")
        education = request.form.get("education")
        username = request.form.get("username")
        password = request.form.get("password")
        # send post to register api
        response = requests.post(api_url + "/register", json={"employee_name": employee_name,
                                                              "email": email,
                                                              "address": address,
                                                              "gender": gender,
                                                              "education": education,
                                                              "username": username,
                                                              "password": password})

        # means user is registered
        if response.status_code == 201:
            flash(response.json()['message'], "success")
            return redirect(url_for('login_view'))
        # means user already exists
        flash(response.json()['message'], "danger")
        return render_template('register.html')

    return render_template("register.html")


# ....logout....
@app.route('/logout')
def logout():
    session.clear()
    flash("You are logged out", "info")
    return redirect(url_for('index'))


# ---------- Admin Pages ----------
# .....Admin HomePage.....
@app.route('/admin')
def admin_home():
    if 'roles' in session:
        if session['roles'] == 'admin':
            return render_template('admins/admin_home.html')

    flash("You are not authorized to view this page", "danger")
    return redirect(url_for('login_view'))


# .....View Employees.....
@app.route('/admin/employees')
def admin_employee_view():
    if 'roles' in session:
        if session['roles'] == 'admin':
            return render_template("admins/admin_view_employees.html")

    flash("You are not authorized to view this page", "danger")
    return redirect(url_for('index'))


# ....Add Employee.....
@app.route('/admin/employees/add', methods=["GET", "POST"])
def admin_employee_add():
    if request.method == "POST":
        # get form data
        employee_name = request.form.get("employee_name")
        email = request.form.get("email")
        address = request.form.get("address")
        gender = request.form.get("gender")
        education = request.form.get("education")
        username = request.form.get("username")
        password = request.form.get("password")
        # send post to register api
        response = requests.post(api_url + "/register", json={"employee_name": employee_name,
                                                              "email": email,
                                                              "address": address,
                                                              "gender": gender,
                                                              "education": education,
                                                              "username": username,
                                                              "password": password})

        # if user is registered
        if response.status_code == 201:
            flash(response.json()['message'], "success")
            return redirect(url_for('admin_employee_view'))
        # if user already exists
        flash(response.json()['message'], "danger")
        return render_template('admins/admin_add_employee.html')
    else:
        # render form
        if 'roles' in session and session['roles'] == "admin":
            return render_template('admins/admin_add_employee.html')

        flash("You are not authorized to view this page", "danger")
        return redirect(url_for('index'))


# ...update employee...
@app.route('/admin/employees/edit/<employee_id>', methods=["GET", "POST"])
def update_employee(employee_id):
    if request.method == "POST":
        # get form data
        employee_name = request.form.get("employee_name")
        email = request.form.get("email")
        address = request.form.get("address")
        gender = request.form.get("gender")
        education = request.form.get("education")
        password = request.form.get("password")

        # get employee id from url
        employee_id = employee_id
        # send get request to api
        response = requests.put(api_url + "/employee/" + str(employee_id), json={"employee_name": employee_name,
                                                                                 "email": email,
                                                                                 "address": address,
                                                                                 "gender": gender,
                                                                                 "education": education,
                                                                                 "password": password})

        # if user is updated
        if response.status_code == 200:
            flash(response.json()['message'], "success")
            return redirect(url_for('admin_employee_view'))
        # something went wrong
        flash(response.json()['message'], "danger")
        return redirect(url_for('update_employee'))

    else:
        # if user is admin
        if 'roles' in session and session['roles'] == "admin":
            # get employee id from url
            employee_id = employee_id
            # send get request to api
            response = requests.get(api_url + "/employee/" + str(employee_id))
            # if user is found
            if response.status_code == 200:
                # get employee
                employee = response.json()['employee']
                # render form
                return render_template('admins/admin_update_employee.html', employee=employee)
            # if user is not found
            flash(response.json()['message'], "danger")
            return redirect(url_for('admin_employee_view'))

        flash("You are not authorized to view this page", "danger")
        return redirect(url_for('index'))


# ...view single employee...
@app.route('/admin/employees/view/<employee_id>', methods=["GET"])
def view_employee(employee_id):
    if 'roles' in session and session['roles'] == "admin":
        # get employee id from url
        employee_id = employee_id
        # send get request to api
        response = requests.get(api_url + "/employee/" + str(employee_id))
        if response.status_code == 404:
            flash('Employee not found', 'danger')
            return redirect(url_for('admin_employee_view'))
        # get employee
        employee = response.json()['employee']
        # render form
        return render_template('admins/admin_view_employee.html', employee=employee)

    # not authorized
    flash("You are not authorized to view this page", "danger")
    return redirect(url_for('index'))


# ....delete employee...
@app.route('/admin/employees/delete/<employee_id>', methods=["GET"])
def delete_employee(employee_id):
    if 'roles' in session and session['roles'] == "admin":
        # get employee id from url
        employee_id = employee_id
        # send get request to api
        response = requests.delete(api_url + "/employee/" + str(employee_id))
        # if user is deleted
        if response.status_code == 200:
            flash(response.json()['message'], "success")
            return redirect(url_for('admin_employee_view'))
        # something went wrong
        flash(response.json()['message'], "danger")
        return redirect(url_for('admin_employee_view'))
    # not authorized
    flash("You are not authorized to view this page", "danger")
    return redirect(url_for('index'))


# --------------------------------------------------------------------------------------------------------------------

# -----------------EMPLOYEE ROUTES-----------------
# ...home...
@app.route('/employee', methods=["GET"])
def employee_home():
    if 'roles' in session:
        if session['roles'] == 'employee':
            return render_template('employees/employee.html')
        else:
            # not authorized
            flash('You are not employee!', 'danger')
            return redirect(url_for('admin_home'))
    # redirect to login page
    flash('You are not logged in', 'danger')
    return redirect(url_for('login_view'))


# ....view profile....
@app.route('/employee/view', methods=["GET"])
def employee_profile():
    if 'roles' in session:
        if session['roles'] == 'employee':
            # send get request to api
            response = requests.get(api_url + "/employee/" + str(session['employee_id']))
            # get employee
            employee = response.json()['employee']
            # render form
            return render_template('employees/employee_profile.html', employee=employee)
        else:
            # not authorized
            flash('You are not employee!', 'danger')
            return redirect(url_for('admin_home'))
    # redirect to login page
    flash('You are not logged in', 'danger')
    return redirect(url_for('login_view'))


# ...update profile...
@app.route('/employee/edit', methods=["GET", "POST"])
def employee_update_profile():
    if 'roles' in session:
        if session['roles'] == 'employee':
            if request.method == "POST":
                # get form data
                employee_name = request.form.get("employee_name")
                email = request.form.get("email")
                address = request.form.get("address")
                gender = request.form.get("gender")
                education = request.form.get("education")
                password = request.form.get("password")
                # send request to api
                response = requests.put(api_url + "/employee/" + str(session['employee_id']),
                                        json={"employee_name": employee_name,
                                              "email": email,
                                              "address": address,
                                              "gender": gender,
                                              "education": education,
                                              "password": password})

                # if user is updated
                if response.status_code == 200:
                    flash(response.json()['message'], "success")
                    return redirect(url_for('employee_profile'))
                # something went wrong
                flash(response.json()['message'], "danger")
                return redirect(url_for('employee_update_profile'))
            else:
                # send get request to api
                response = requests.get(api_url + "/employee/" + str(session['employee_id']))
                # get employee
                employee = response.json()['employee']
                # render form
                return render_template('employees/employee_update_profile.html', employee=employee)
        else:
            # not authorized
            flash('You are not employee!', 'danger')
            return redirect(url_for('admin_home'))
    # redirect to login page
    flash('You are not logged in', 'danger')
    return redirect(url_for('login_view'))


if __name__ == '__main__':
    app.run()
