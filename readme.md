# Python Flask Rest API using JWT

## About this api

This is a simple pythong api using flask and jwt with http authentication.

#### Framework: Flask 1.1.1
#### Language: Python 2.7
#### Database: Sqlite3

## To run
- Type this line:
```
python api.py
```

## End Points
- POST /user/add
    ```
    Input example: {"user_name": "USER_NAME", "password": "USER_PASSWORD"}
    Output exmaple: {"Added user": "user_name"}
    ```
- POST /user/update
    ```
    Input example: {"user_name": "USER_NAME", "password": "USER_PASSWORD", "newpassword": "USER_NEW_PASSWORD"}
    Output exmaple: {"Updated password for user": "USER_NAME"}
    ```
- GET /login
- GET /getallusers
 