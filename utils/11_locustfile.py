from locust import HttpUser, TaskSet, task, between

class UserBehavior(TaskSet):
    @task(1)
    def index(self):
        self.client.get("/")

    @task(2)
    def login(self):
        self.client.post("/login", {"username": "asd", "password": "asd"})

class WebsiteUser(HttpUser):
    tasks = [UserBehavior]
    wait_time = between(1, 5)



# from flask import Flask, render_template, request, redirect, url_for, flash

# app = Flask(__name__)
# app.secret_key = 'your_secret_key'

# @app.route('/')
# def index():
#     return "Hello, World!"

# @app.route('/login', methods=['GET', 'POST'])
# def login():
#     if request.method == 'POST':
#         # Simulate login action
#         username = request.form['username']
#         password = request.form['password']
#         # Add some logic for handling login
#         return redirect(url_for('index'))
#     return "Login Page"

# if __name__ == '__main__':
#     app.run(debug=True)

