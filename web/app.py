from flask import Flask, request, jsonify
from flask_restful import Api, Resource
from pymongo import MongoClient
import bcrypt
import numpy as np
import requests


from keras.api.applications import InceptionV3
from keras.api.applications.inception_v3 import preprocess_input
from keras.api.applications import imagenet_utils
from keras.api.preprocessing.image import img_to_array
from PIL import Image
from io import BytesIO

#pretrained model
pretrained_model =  InceptionV3(weights="imagenet")



app = Flask(__name__)
api = Api(app)


#mongodb client

client =  MongoClient("mongodb://db:27017")


#new db and collection
db = client.ImageRecognition
users = db["Users_1"]


def user_exists(username):
    if users.count_documents({"username": username}) == 0:
        return False
    else:
        return True


def verify_password(username, password):
    if not user_exists(username):
        return False

    hashed_pw = users.find({
        "username": username
    })[0]['password']

    if bcrypt.hashpw(password.encode('utf8',hashed_pw)) == hashed_pw:
        return True
    else:
        return False


def verify_user(username, password):
    if not user_exists(username):
        return generate_return_dictionary(301, "Invalid Username."), True

    correct_pw = verify_password(username, password)

    if not correct_pw:
        return generate_return_dictionary(302, "Invalid Password."), True


    return None, False



def generate_return_dictionary(status, msg):
    return {
        "status": status,
        "msg": msg
    }


"""class Register:

    def post(self):
        #get posted data
        posted_data = request.get_json()

        #get username and password
        username = posted_data["username"]
        password = posted_data["password"]

        #check user exists
        if user_exists(username):
            return jsonify({
                "status": 301,
                "message": "Please try a different username"
            })

        # hash password
        hashed_password = bcrypt.hashpw(password.encode('utf8'), bcrypt.gensalt())


        #insert into DB
        users.insert_one({
            "username": username,
            "password": hashed_password,
            "tokens": 4
        })

        return jsonify({
            "status": 200,
            "message": "User creation is success."
        })"""

class Register(Resource):
    def post(self):
        # Get posted data
        posted_data = request.get_json()

        # Get username and password
        username = posted_data["username"]
        password = posted_data["password"]

        # Check user exists
        if user_exists(username):
            return jsonify({
                "status": 301,
                "message": "Please try a different username"
            })

        # Hash password
        hashed_password = bcrypt.hashpw(password.encode('utf8'), bcrypt.gensalt())

        # Insert into DB
        users.insert_one({
            "username": username,
            "password": hashed_password,
            "tokens": 4
        })

        return jsonify({
            "status": 200,
            "message": "User creation is successful."
        })

class Classify(Resource):
    def post(self):
        posted_data = request.get_json()

        #get username, password, URL
        username = posted_data["username"]
        password = posted_data["password"]
        url  = posted_data["url"]


        # authenticate user
        response, error = verify_user(username, password)


        #check user tokens
        tokens = users.find({"Username": username})[0]["tokens"]

        if tokens <=0:
            return jsonify(generate_return_dictionary(303, "Not enough Tokens"))

        #check url
        if not url:
            return jsonify(({"error": "No url provided"}), 400)


        #load the image
        response = requests.get(url)
        img = Image.open(BytesIO(response.content))


        #preprocess - make the image perfect for prediction
        img = img.resize((299,299))
        img_array = img_to_array(img)
        img_array = np.expand_dims(img_array, axis = 0)
        img_array = preprocess_input(img_array)


        #prediction
        prediction = pretrained_model.predict(img_array)
        actual_prediction = imagenet_utils.decode_predictions(prediction, top=5)


        #return classification
        response = {}
        for predictions in actual_prediction[0]:
            response[predictions[1]] = float(predictions[2]*100)


        #deduct tokens

        users.update_one({
            "Username": username
        }, {
            "$set": {
                "Tokens": tokens-1
            }
        })

        return jsonify(response)


class Refill(Resource):
    def post(self):
        posted_data = request.get_json()

        # get username, password, URL
        username = posted_data["username"]
        admin_pw = posted_data["admin_pw"]
        amount = posted_data["amount"]


        #check user
        if not user_exists(username):
            return generate_return_dictionary(301, "Incorrect user name")

        admin_pwd = "abc123"

        if not admin_pw == admin_pwd:
            generate_return_dictionary(302,"Incorrect password")


        #update the token and respond

        users.update_one({
            'username':username}, {
            '$set': {
            'tokens': amount
        }
        }
        )


        return generate_return_dictionary(200, "Success")










api.add_resource(Register, '/register')
api.add_resource(Classify, '/classify')
api.add_resource(Refill, '/refill')

if __name__ == "__main__":
    app.run(host='0.0.0.0')

