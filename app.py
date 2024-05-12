from flask import Flask, render_template, request, redirect, url_for, flash
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///site.db'
app.config['SECRET_KEY'] = 'your_secret_key'
db = SQLAlchemy(app)

# Define User model
class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(20), unique=True, nullable=False)
    password = db.Column(db.String(60), nullable=False)

# Define a list of admin usernames
ADMIN_USERNAMES = ['admin']  # Customize this as needed

# Define Candidate model
class Candidate(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    category = db.Column(db.String(100), nullable=False)
    name = db.Column(db.String(100), nullable=False)

# Define Vote model
class Vote(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    voter_id = db.Column(db.String(20), nullable=False)
    category = db.Column(db.String(100), nullable=False)
    selected_candidate = db.Column(db.String(100), nullable=False)

    def __repr__(self):
        return f"Vote(category={self.category}, selected_candidate={self.selected_candidate}, voter_id={self.voter_id})"

login_manager = LoginManager()
login_manager.init_app(app)

# Create DB
with app.app_context():
    db.create_all()

# Simulated database of users
users = {'user1': {'password': 'password1'}}

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# Define a dictionary to store the candidates for each category
candidates = {
    "President": ["Candidate A", "Candidate B", "Candidate C"],
    "VP Academic Affairs": ["Candidate D", "Candidate E", "Candidate F"],
    "Clubs and Socs Officer": ["Candidate G", "Candidate H", "Candidate I"],
    "VP Welfare and Equality": ["Candidate J", "Candidate K", "Candidate L"],
    "Entertainment Officer": ["Candidate M", "Candidate N", "Candidate O"],
    "Communications Officer": ["Candidate P", "Candidate Q", "Candidate R"]
}

# Define a dictionary to store the votes for each category
votes = {
    "President": {},
    "VP Academic Affairs": {},
    "Clubs and Socs Officer": {},
    "VP Welfare and Equality":{},
    "Communications Officer":{},
    "Entertainment Officer":{},
}

# Function to calculate voting results
def calculate_voting_results():
    voting_results = {}
    # Retrieve all votes from the database
    votes = Vote.query.all()
    # Iterate over votes and count votes for each candidate in each category
    for vote in votes:
        category = vote.category
        selected_candidate = vote.selected_candidate
        if category not in voting_results:
            voting_results[category] = {}
        if selected_candidate not in voting_results[category]:
            voting_results[category][selected_candidate] = 0
        voting_results[category][selected_candidate] += 1
    return voting_results

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = User.query.filter_by(username=username).first()
        if user and check_password_hash(user.password, password):
            login_user(user)
            if username in ADMIN_USERNAMES:
                flash('Admin login successful!')
                return redirect(url_for('result'))
            else:
                flash('Login successful!')
                return redirect(url_for('vote'))
        else:
            flash('Invalid username or password!')
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('You have been logged out!')
    return redirect(url_for('index'))

@app.route('/vote', methods=['GET', 'POST'])
@login_required
def vote():
    if request.method == 'POST':
        voter_id = request.form['voter_id']
        for category in candidates:
            selected_candidate = request.form.get(category)
            if selected_candidate:
                if voter_id in votes[category]:
                    flash('You have already voted for this category.')
                else:
                    new_vote = Vote(voter_id=voter_id, category=category, selected_candidate=selected_candidate)
                    db.session.add(new_vote)
                    db.session.commit()
                    flash('Vote recorded successfully.')
        return redirect(url_for('index'))
    return render_template('vote.html', candidates=candidates)

@app.route('/result')
@login_required
def result():
    # Calculate the number of votes each candidate
    voting_results = calculate_voting_results()

    # Pass voting results to template
    return render_template('result.html', voting_results=voting_results)

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        hashed_password = generate_password_hash(password)
        # Check if username already exists
        if User.query.filter_by(username=username).first():
            flash('Username already exists. Please choose a different one.')
            return redirect(url_for('register'))
        # Create new user
        new_user = User(username=username, password=hashed_password)
        db.session.add(new_user)
        db.session.commit()
        flash('Registration successful! You can now log in.')
        return redirect(url_for('login'))
    return render_template('registration.html')

if __name__ == '__main__':
    app.run(debug=True)
