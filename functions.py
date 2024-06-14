from flask_login import UserMixin
def UserModel(db):
    class User(db.Model, UserMixin):
        id = db.Column(db.Integer, primary_key=True)
        fullname = db.Column(db.String(100), nullable=False)
        mobilenum = db.Column(db.String(20), unique=True, nullable=False)
        password_hash = db.Column(db.String(128), nullable=False)
        point = db.Column(db.Integer, default=0)

    return User


"""
//  Code Explanation
--> def create_profile_db(db)
    # Here i'm importing `db` from app.py --> db = SQLAlchemy(app)
    The function paramter, `db` inherits everything from `db`

"""
def ReportModel(db):
    class Report(db.Model):
        __tablename__ = 'reports'
        id = db.Column(db.Integer, primary_key=True)
        name = db.Column(db.String(100))
        contact = db.Column(db.String(100))
        victim_name = db.Column(db.String(255))
        address = db.Column(db.String(255))
        state = db.Column(db.String(100))
        district = db.Column(db.String(100))
        block = db.Column(db.String(100))
        location = db.Column(db.String(100))
        child_photo = db.Column(db.String(255))
        more_details = db.Column(db.Text)

    return Report
