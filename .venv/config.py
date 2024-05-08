# from flaskext.mysql import MySQL

# app = Flask(_name_)

# app.config['MYSQL_DATABASE_USER'] = 'root'
# app.config['MYSQL_DATABASE_PASSWORD'] = ''
# app.config['MYSQL_DATABASE_DB'] = 'gohelp'
# app.config['MYSQL_DATABASE_HOST'] = 'localhost'

# mysql = MySQL()
# mysql.init_app(app)
from flask import Flask
app = Flask(__name__)
@app.route('/')
def hello_world():
    return 'Hello world!'