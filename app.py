from flask import Flask, jsonify, request
from flask_jwt_extended import create_access_token, JWTManager, jwt_required, get_jwt_identity
from flask_bcrypt import Bcrypt
import joblib 
import numpy as np

#Scalers for the models
scaler = joblib.load('scaler.joblib')
scalerHoursAndAttendance=joblib.load('scalerHoursStudiedANDAttendance.joblib')
scalerHours=joblib.load('scalerHoursStudied.joblib')


model_filename = 'exam_score.joblib'
model_filename_attendance = 'exam_score_attendance.joblib'
model_filename_hours_studied_and_attendance = 'exam_scoreHoursStudied_And_Attendance.joblib'

try:
    loaded_model = joblib.load(model_filename)
    print("Modellen laddad")
except FileNotFoundError:
    print("Error")

try:
    loaded_model_attendance = joblib.load(model_filename_attendance)
    print("Modellen laddad")
except FileNotFoundError:
    print("Error")


try:
    loaded_model_hours_studied_and_attendance = joblib.load(model_filename_hours_studied_and_attendance)
    print("Modellen laddad")
except FileNotFoundError:
    print("Error")


app = Flask(__name__)

app.config["JWT_SECRET_KEY"] = "super-hemlig-kod"
jwt = JWTManager(app)
bcrypt = Bcrypt(app)

hashed_password_josefin = bcrypt.generate_password_hash("123456").decode('utf-8')
hashed_password_anna = bcrypt.generate_password_hash("pasword").decode('utf-8')

print(hashed_password_josefin)
print(hashed_password_anna)

users = {
    "josefin" : hashed_password_josefin,
    "anna" : hashed_password_anna
}


@app.route("/login", methods=["POST"])
def login():
    username = request.json.get("username")
    password = request.json.get("password")
   
    stored_hashed_password = users.get(username)
   
    if not bcrypt.check_password_hash(stored_hashed_password, password):
        return jsonify({"msg": "Bad username or password"}), 401
    
    access_token = create_access_token(identity=username)
    return jsonify(access_token=access_token)
    


#Welcome message
@app.route('/', methods=['GET'])
def get_hello():
    return 'Prediction of exam score'

#To predict an exam score based on Hours studied
@app.route('/examScoreHoursStudied', methods=['POST'])
@jwt_required()
def examScoreHoursStudied():
    data = request.get_json()
    hours_studied = data.get('hours_studied', 0)
    if hours_studied is None:
            return jsonify({'error': 'Missing hours studied value'}), 400
    
    hours_studied_scaled = scalerHours.transform(np.array([[hours_studied]]))
    predict = loaded_model.predict(hours_studied_scaled)

    return jsonify({
            'hours_studied': hours_studied,
            'predicted_exam_score': round(float(predict), 2)
        })


#To predict an exam score based on attendance
@app.route('/examScoreAttendance', methods=['POST'])
@jwt_required()
def examScoreAttendance():
    data = request.get_json()
    attendance = data.get('attendance', 0)
    if attendance is None:
            return jsonify({'error': 'Missing attendance value'}), 400
    attendance_scaled = scaler.transform(np.array([[attendance]]))

    
    predict = loaded_model_attendance.predict(attendance_scaled)
   
    return jsonify({
            'attendance': attendance,
            'predicted_exam_score': round(float(predict), 2)
        })


#To predict an exam score based on Hours studied and Attendance
@app.route('/examScoreHoursStudiedAndAttendance', methods=['POST'])
@jwt_required()
def examScoreHoursStudiedAndAttendance():
    data = request.get_json()
    hours_studied = data.get('hours_studied', 0)
    attendance = data.get('attendance', 0)
    if hours_studied is None:
            return jsonify({'error': 'Missing hours studied value'}), 400
    if attendance is None:
            return jsonify({'error': 'Missing attendance value'}), 400
    
    data_scaled = scalerHoursAndAttendance.transform(np.array([[hours_studied, attendance]]))
    


    predict = loaded_model_hours_studied_and_attendance.predict(data_scaled)

    return jsonify({
            'hours_studied': hours_studied,
            'attendance': attendance,
            'predicted_exam_score': round(float(predict[0]), 2)
        })

    

if __name__ == '__main__':
    app.run(debug=True)
