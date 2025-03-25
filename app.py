from flask import Flask, render_template, request, redirect, url_for, jsonify, session, flash
from flask_mail import Mail, Message
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
import hashlib, json, time
from datetime import datetime

app = Flask(__name__)
app.secret_key = 'your_secret_key'  # Change for production!

# Set up configuration before initializing extensions
app.config['MAIL_SERVER'] = 'smtp.example.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USERNAME'] = 'your_email@example.com'
app.config['MAIL_PASSWORD'] = 'your_password'
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USE_SSL'] = False

app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///data.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

mail = Mail(app)

# Create the SQLAlchemy object without the app
db = SQLAlchemy()
# Now initialize it with the app
db.init_app(app)

# (The rest of your code follows here)


# -----------------------
# Models
# -----------------------

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(120), unique=True, nullable=False)
    username = db.Column(db.String(80), nullable=False)
    password_hash = db.Column(db.String(128), nullable=False)
    balance = db.Column(db.Float, default=1000000.0)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)  # New field

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)
    
    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

# -----------------------
# Custom Template Filter
# -----------------------
@app.template_filter('datetimeformat')
def datetimeformat(value, format='%Y-%m-%d %H:%M:%S'):
    try:
        return datetime.fromtimestamp(float(value)).strftime(format)
    except Exception:
        return value

# -----------------------
# Blockchain Implementation (unchanged)
# -----------------------

class Block:
    def __init__(self, index, transactions, timestamp, previous_hash, nonce=0):
        self.index = index
        self.transactions = transactions
        self.timestamp = timestamp
        self.previous_hash = previous_hash
        self.nonce = nonce
        self.hash = self.compute_hash()

    def compute_hash(self):
        block_string = json.dumps(self.__dict__, sort_keys=True)
        return hashlib.sha256(block_string.encode()).hexdigest()

class Blockchain:
    difficulty = 2  # Mining difficulty
    def add_new_transaction(self, transaction):
        self.unconfirmed_transactions.append(transaction)
        print("Transaction added to unconfirmed transactions:", self.unconfirmed_transactions)

    def __init__(self):
        self.unconfirmed_transactions = []  # Pending transactions
        self.chain = []
        self.create_genesis_block()

    def create_genesis_block(self):
        genesis_block = Block(0, [], time.time(), "0")
        self.chain.append(genesis_block)

    @property
    def last_block(self):
        return self.chain[-1]

    def proof_of_work(self, block):
        block.nonce = 0
        computed_hash = block.compute_hash()
        while not computed_hash.startswith('0' * Blockchain.difficulty):
            block.nonce += 1
            computed_hash = block.compute_hash()
        return computed_hash

    def add_block(self, block, proof):
        previous_hash = self.last_block.hash
        if previous_hash != block.previous_hash:
            return False
        if not proof.startswith('0' * Blockchain.difficulty):
            return False
        block.hash = proof
        self.chain.append(block)
        return True

    def add_new_transaction(self, transaction):
        self.unconfirmed_transactions.append(transaction)

    def mine(self):
        if not self.unconfirmed_transactions:
            return False

        new_block = Block(
            index=self.last_block.index + 1,
            transactions=self.unconfirmed_transactions,
            timestamp=time.time(),
            previous_hash=self.last_block.hash
        )
        proof = self.proof_of_work(new_block)
        self.add_block(new_block, proof)
        self.unconfirmed_transactions = []
        return new_block.index

blockchain = Blockchain()

# -----------------------
# Helper Functions & Context Processors
# -----------------------

def current_user():
    user_email = session.get('user_email')
    if user_email:
        return User.query.filter_by(email=user_email).first()
    return None

@app.context_processor
def inject_user():
    return dict(current_user=current_user)

def login_required(f):
    from functools import wraps
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if current_user() is None:
            flash("Please login to access this page.", "warning")
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

# -----------------------
# Routes for Authentication & Registration
# -----------------------

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        email = request.form.get('email').lower()
        username = request.form.get('username')
        password = request.form.get('password')
        if User.query.filter_by(email=email).first():
            flash("Email already registered.", "danger")
            return redirect(url_for('register'))
        # Create a new user with an initial balance of 1,000,000
        user = User(email=email, username=username, balance=1000000.0)
        user.set_password(password)
        db.session.add(user)
        db.session.commit()
        # Send registration email (if configured)
        try:
            msg = Message(
                "Welcome to Decentralized Banking System",
                sender=app.config['MAIL_USERNAME'],
                recipients=[email]
            )
            msg.body = f"Hello {username},\n\nThank you for registering. Your initial balance is 1,000,000 units."
            mail.send(msg)
        except Exception as e:
            print("Email sending failed:", e)
        flash("Registration successful! Check your email for details.", "success")
        return redirect(url_for('login'))
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form.get('email').lower()
        password = request.form.get('password')
        user = User.query.filter_by(email=email).first()
        if user and user.check_password(password):
            session['user_email'] = email
            flash("Logged in successfully!", "success")
            return redirect(url_for('index'))
        flash("Invalid credentials.", "danger")
        return redirect(url_for('login'))
    return render_template('login.html')

@app.route('/logout')
def logout():
    user = current_user()
    if user:
        # Remove all transactions related to the user
        global blockchain
        blockchain.unconfirmed_transactions = [
            tx for tx in blockchain.unconfirmed_transactions if tx['sender'] != user.email and tx['receiver'] != user.email
        ]
        
        # Remove blocks containing the user's transactions
        new_chain = [blockchain.chain[0]]  # Keep the Genesis Block
        for block in blockchain.chain[1:]:
            filtered_transactions = [
                tx for tx in block.transactions if tx['sender'] != user.email and tx['receiver'] != user.email
            ]
            if filtered_transactions:
                block.transactions = filtered_transactions
                block.hash = block.compute_hash()  # Recompute hash after modifying transactions
                new_chain.append(block)
        
        blockchain.chain = new_chain  # Update blockchain with filtered blocks

    session.pop('user_email', None)
    flash("Your transaction history has been deleted, and you have been logged out.", "info")
    return redirect(url_for('login'))

# -----------------------
# Main Application Routes
# -----------------------

@app.route('/')
@login_required
def index():
    return render_template('index.html')

@app.route('/chain_data')
@login_required
def chain_data():
    chain_data = []
    for block in blockchain.chain:
        chain_data.append({
            'index': block.index,
            'transactions': block.transactions,
            'timestamp': block.timestamp,
            'previous_hash': block.previous_hash,
            'nonce': block.nonce,
            'hash': block.hash
        })
    return jsonify(chain=chain_data)

@app.route('/new_transaction', methods=['POST'])
@login_required
def new_transaction():
    tx_data = request.form
    print("Received transaction data:", tx_data)  # Debug print
    sender_user = current_user()
    sender = sender_user.email
    receiver = tx_data.get("receiver").lower()
    try:
        amount = float(tx_data.get("amount"))
    except (TypeError, ValueError):
        flash("Invalid amount.", "danger")
        return redirect(url_for('index'))

    # Validate that receiver is registered
    receiver_user = User.query.filter_by(email=receiver).first()
    if receiver_user is None:
        flash("Receiver email is not registered", "danger")
        return redirect(url_for('index'))

    if sender == receiver:
        flash("Cannot send money to yourself", "danger")
        return redirect(url_for('index'))

    if sender_user.balance < amount:
        flash("Insufficient balance for transaction.", "danger")
        return redirect(url_for('index'))

    print(f"Deducting {amount} from {sender} and crediting {receiver}")
    # Deduct sender's balance and credit receiver's balance
    sender_user.balance -= amount
    receiver_user.balance += amount
    db.session.commit()

    # Record the transaction on the blockchain
    transaction = {
        "sender": sender,
        "receiver": receiver,
        "amount": amount,
        "timestamp": time.time()
    }
    blockchain.add_new_transaction(transaction)
    blockchain.mine()
    print("Transaction recorded on blockchain:", transaction)

    if request.headers.get("X-Requested-With") == "XMLHttpRequest":
        return jsonify({"message": "Transaction submitted successfully"}), 200
    flash("Transaction submitted successfully", "success")
    return redirect(url_for('index'))

@app.route('/mine', methods=['GET'])
@login_required
def mine():
    if not blockchain.unconfirmed_transactions:
        print("No pending transactions to mine.")
        flash("No transactions to mine.", "info")
        return redirect(url_for('index'))
    
    print("Pending transactions:", blockchain.unconfirmed_transactions)
    result = blockchain.mine()
    if not result:
        flash("No transactions to mine.", "info")
        return redirect(url_for('index'))
    print("New block mined with index:", result)
    flash("Block mined successfully!", "success")
    return redirect(url_for('index'))

# -----------------------
# User-specific Routes
# -----------------------

@app.route('/profile')
@login_required
def profile():
    user = current_user()
    return render_template('profile.html', user=user)

@app.route('/balance')
@login_required
def balance():
    user = current_user()
    return render_template('balance.html', user=user)

@app.route('/accounts')
@login_required
def accounts():
    # Retrieve all user accounts from the database
    all_users = User.query.all()
    return render_template('accounts.html', users=all_users)

@app.route('/account/<int:user_id>')
@login_required
def account_detail(user_id):
    # Retrieve the selected user or return a 404 if not found
    user = User.query.get_or_404(user_id)
    # Filter the blockchain transactions related to this user's email
    history = []
    for block in blockchain.chain:
        for tx in block.transactions:
            if tx.get('sender') == user.email or tx.get('receiver') == user.email:
                history.append(tx)
    return render_template('account_detail.html', user=user, transactions=history)

@app.route('/transaction_history')
@login_required
def transaction_history():
    user_email = current_user().email
    history = []
    for block in blockchain.chain:
        for tx in block.transactions:
            if tx.get('sender') == user_email or tx.get('receiver') == user_email:
                history.append(tx)
    return render_template('transaction_history.html', transactions=history)

# -----------------------
# Run the Application
# -----------------------
if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True, use_reloader=False)

