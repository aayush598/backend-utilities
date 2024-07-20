from flask import Flask, render_template

app = Flask(__name__)

@app.route('/')
def hello():
    return 'Hello World!'

# Error handling
@app.errorhandler(404)
def page_not_found(e):
    return render_template('error_404.html'), 404

@app.errorhandler(500)
def internal_server_error(e):
    return render_template('error_500.html'), 500

if __name__ == '__main__':
    app.run(debug=True)  # Set debug=True for detailed error messages
