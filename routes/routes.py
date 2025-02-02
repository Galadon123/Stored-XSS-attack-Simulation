from flask import render_template, request, redirect, url_for, session, flash
from models.models import db, User, Comment

def init_routes(app):
    @app.route('/login', methods=['GET', 'POST'])
    def login():
        if request.method == 'POST':
            user = User.query.filter_by(
                username=request.form['username'],
                password=request.form['password']
            ).first()
            
            if user:
                session['logged_in'] = True
                session['username'] = user.username
                return redirect(url_for('home'))
            flash('Invalid username or password')
        return render_template('login.html')

    @app.route('/signup', methods=['GET', 'POST'])
    def signup():
        if request.method == 'POST':
            username = request.form['username']
            if User.query.filter_by(username=username).first():
                flash('Username already exists')
                return render_template('signup.html')
            
            user = User(
                username=username,
                password=request.form['password']
            )
            db.session.add(user)
            db.session.commit()
            return redirect(url_for('login'))
        return render_template('signup.html')

    @app.route('/logout')
    def logout():
        session.clear()
        return redirect(url_for('login'))

    @app.route('/')
    def home():
        if not session.get('logged_in'):
            return redirect(url_for('login'))
        comments = Comment.query.order_by(Comment.timestamp.desc()).all()
        return render_template('main.html', comments=comments)

    @app.route('/comment', methods=['POST'])
    def add_comment():
        if not session.get('logged_in'):
            return redirect(url_for('login'))
        
        content = request.form.get('content')
        if content:
            comment = Comment(content=content)
            db.session.add(comment)
            db.session.commit()
        return redirect(url_for('home'))