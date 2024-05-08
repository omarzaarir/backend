from flask import Flask, jsonify
import pymysql 

app = Flask(__name__)

host = 'localhost'
user = 'sally'
password = 'sally123456'
database = 'gohelp'
    
@app.route('/')
def index():
    return 'Hello, World!'

@app.route('/interests')
def get_interests():
    
    try: 
        connection = pymysql.connect(
            host=host,
            user=user, 
            password=password,
            database=database
        )
        with connection.cursor(pymysql.cursors.DictCursor) as cursor:
            query = "SELECT * FROM interests"
            cursor.execute(query)
            interests = cursor.fetchall()
        connection.close()
        return jsonify(interests)
    except pymysql.Error as e:
        return jsonify({'error': str(e)}), 500

if __name__ == '_main_':
    app.run(debug=True)

