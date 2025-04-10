from flask import *

# Initialize the Flask app
app = Flask(__name__)

@app.route('/')
def index():
    title = request.args.get('title', 'Default Title')
    return render_template('index.html', title=title)

@app.get('/about')
def about():
    return render_template('about.html', title='About Us')

@app.post('/postbutton')
def postbutton():
    # Handle the post request here
    return jsonify({"message": "Post request received!"})

