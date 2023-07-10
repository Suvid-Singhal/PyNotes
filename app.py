from flask import Flask, redirect,render_template, redirect, flash, request
from flask_sqlalchemy import SQLAlchemy
from datetime import datetime
from flask_wtf import FlaskForm
from wtforms import StringField, SubmitField, PasswordField, BooleanField, ValidationError
from wtforms.validators import DataRequired, EqualTo, Length, Email
from werkzeug.security import generate_password_hash, check_password_hash
from wtforms.widgets import TextArea
from flask_login import UserMixin, UserMixin,login_user,LoginManager,login_required,logout_user,current_user
from flask_ckeditor import CKEditor, CKEditorField

app=Flask(__name__)
ckeditor=CKEditor(app)
app.config['SQLALCHEMY_DATABASE_URI']="sqlite:///pynotes.db"
app.config['SQLALCHEMY_TRACK_MODIFICATIONS']=False
app.config['SECRET_KEY']="fbsdhfvsdhf6t7867858tyfkjkannj"


db=SQLAlchemy(app)

#Users Model
class Users(db.Model,UserMixin):
    id=db.Column(db.Integer,primary_key=True)
    username=db.Column(db.String(20),nullable=False,unique=True)
    name=db.Column(db.String(200),nullable=False)
    email=db.Column(db.String(120),nullable=False,unique=True)
    #Password stuff
    password_hash=db.Column(db.String(128))

    @property
    def password(self):
        raise AttributeError('Password is not a readable attribute!')
    @password.setter
    def password(self,password):
        self.password_hash=generate_password_hash(password)
    
    def verify_password(self,password):
        return check_password_hash(self.password_hash,password)

    def __repr__(self):
        return '<Name %r>' % self.name

#Notes Model
class Notes(db.Model):
    id=db.Column(db.Integer,primary_key=True)
    title=db.Column(db.String(200))
    content=db.Column(db.Text)
    username=db.Column(db.String(255))
    date=db.Column(db.String(50),default=datetime.utcnow().strftime("%b %d, %Y %H:%M:%S"))

class UserForm(FlaskForm):
    name=StringField("Name",validators=[DataRequired()])
    username=StringField("Username",validators=[DataRequired()])
    email=StringField("Email",validators=[DataRequired(),Email(message="Invalid email")])
    password_hash=PasswordField("Password",validators=[DataRequired()])
    password_hash2=PasswordField("Confirm Password",validators=[DataRequired(),EqualTo('password_hash',message="Passwords do not match!")])
    submit=SubmitField("Submit")

class NoteForm(FlaskForm):
    title=StringField("Title",validators=[DataRequired()],render_kw={"placeholder":"Title"})
    content=CKEditorField('Content',validators=[DataRequired()])
    submit=SubmitField("Submit")

class LoginForm(FlaskForm):
    username=StringField("Username",validators=[DataRequired()],render_kw={"placeholder":"Username"})
    password=PasswordField("Password",validators=[DataRequired()],render_kw={"placeholder":"Password"})
    submit=SubmitField("Submit")

#Flask Login Configuration
login_manager=LoginManager()
login_manager.init_app(app)
login_manager.login_view='login'

@login_manager.user_loader
def loaduser(user_id):
    return Users.query.get(int(user_id))


@app.route("/",methods=['GET','POST'])
def index():
    #print(current_user)
    try:
        return render_template("home.html")
    except:
        return render_template("home.html")
    '''
    if request.method=="POST":
        title=request.form['title']
        content=request.form['content']
        note=PyNotes(title=title,content=content)
        db.session.add(note)
        db.session.commit()
        return redirect("/manage")'''
    

@app.route("/register",methods=['GET','POST'])
def add_user():
    form=UserForm()
    if form.validate_on_submit():
        user=Users.query.filter_by(email=form.email.data).first()
        user2=Users.query.filter_by(username=form.username.data).first()
        if user==None and user2==None:
            #Hash the password
            hashed_pw=generate_password_hash(form.password_hash.data,"sha256")
            user=Users(username=form.username.data,name=form.name.data,email=form.email.data,password_hash=hashed_pw)
            db.session.add(user)
            db.session.commit()
            form.username.data=''
            form.name.data=''
            form.email.data=''
            form.password_hash.data=''
            flash("Registration Successful!")
            return redirect("/")
        elif user is not None:
            flash("An account with this email already exists!")
            return render_template("register.html",form=form)
        else:
            flash("Username already taken!")
            return render_template("register.html",form=form)
    errors = [{'field': key, 'messages': form.errors[key]} for key in form.errors.keys()] if form.errors else []
    if len(errors)>0:
        flash(errors[0]['messages'][0])
        return render_template("register.html",form=form)
    return render_template("register.html",form=form)


@app.route("/add",methods=['GET','POST'])
@login_required
def add_note():
    form=NoteForm()

    if form.validate_on_submit():
        note=Notes(title=form.title.data,content=form.content.data,username=current_user.username)
        #Clear the form
        form.title.data=''
        form.content.data=''

        db.session.add(note)
        db.session.commit()
        flash("Note Added Successfully!")
        return redirect("/notes")
    return render_template("add.html",form=form)


@app.route('/about')
def about():
    return render_template("about.html")

@app.route('/notes')
@login_required
def my_notes():
    allNotes=Notes.query.filter_by(username=current_user.username)
    return render_template("notes.html",allNotes=allNotes)

@app.route('/login',methods=['GET','POST'])
def login():
    form=LoginForm()
    if form.validate_on_submit():
        user=Users.query.filter_by(username=form.username.data).first()
        if user:
            if check_password_hash(user.password_hash,form.password.data):
                login_user(user)
                flash("Logged in Successfully!!")
                return redirect("/notes")
            else:
                flash("Wrong Username!")
        else:
            flash("Wrong Username/Password!")
    return render_template("login.html",form=form)

@app.route('/delete/<int:id>')
@login_required
def delete(id):
    allNotes=Notes.query.filter_by(id=id,username=current_user.username).first()
    try:
        db.session.delete(allNotes)
        db.session.commit()
    except:
        flash("This action is prohibited!")
    return redirect("/notes")

@app.route("/logout",methods=['GET','POST'])
@login_required
def logout():
    logout_user()
    flash("You have been Logged out Successfully!")
    return redirect("/")

@app.route('/manage')
@login_required
def manage():
    allNotes=Notes.query.filter_by(username=current_user.username)
    return render_template("manage.html",allNotes=allNotes)

@app.route('/update/<int:id>',methods=['GET','POST'])
@login_required
def update(id):
    note=Notes.query.filter_by(id=id,username=current_user.username).first()
    if note==None:
        flash("This action is prohibited!")
        return redirect("/")
    form=NoteForm()
    if form.validate_on_submit():
        note.title=form.title.data
        note.content=form.content.data
        note.date=datetime.utcnow().strftime("%b %d, %Y %H:%M:%S")
        db.session.add(note)
        db.session.commit()
        flash("Note has been updated Suceessfully!")  
        return redirect("/notes")
    form.title.data=note.title
    form.content.data=note.content
    return render_template("update.html",form=form)

@app.route('/note/<string:id>/')
@login_required
def my_note(id):
    note=Notes.query.filter_by(id=id,username=current_user.username).first()
    if note==None:
        flash("This action is prohibited!")
        return redirect("/")
    return render_template("note.html",note=note)


'''
@app.route('/manage')
def manage():
    allNotes=PyNotes.query.all()
    return render_template("manage.html",allNotes=allNotes)

@app.route('/add')
def add():
    return render_template("add.html")

@app.route('/delete/<int:sno>')
def delete(sno):
    allNotes=PyNotes.query.filter_by(sno=sno).first()
    db.session.delete(allNotes)
    db.session.commit()
    return redirect("/manage")

@app.route('/update/<int:sno>',methods=['GET','POST'])
def update(sno):
    if request.method=="POST":
        title=request.form['title']
        content=request.form['content']
        note=PyNotes.query.filter_by(sno=sno).first()
        note.title = title
        note.content = content
        db.session.add(note)
        db.session.commit()
        return redirect("/manage")
    note=PyNotes.query.filter_by(sno=sno).first()
    return render_template("update.html",note=note)
'''

'''@app.route('/note/<string:id>/')
def my_note(id):
    return render_template("note.html",id=id)'''

if __name__=='__main__':
    app.run(debug=False)
