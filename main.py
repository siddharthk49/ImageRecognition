from pymongo import MongoClient

client =  MongoClient("mongodb://db:27017")

db = client.ImageRecognition
users = db["Users_1"]


users.insert_one({
            "username": "abcd",
            "password": "12345",
            "tokens": 4
        })


print("Done!")