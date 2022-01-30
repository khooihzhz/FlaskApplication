from faker import Faker
import requests

fake = Faker()
# api url
BASE_URL = "http://localhost:5000/api"

# categories
education = ['degree', 'master', 'phd']
gender = ['male', 'female']

# list amount of fake data
AMOUNT_OF_FAKE_DATA = 10

# generate fake data here
for i in range(AMOUNT_OF_FAKE_DATA):
    fake_json = {
        "employee_name": fake.name(),
        "email": fake.email(),
        "address": fake.street_address(),
        "gender": gender[fake.random_int(0, 1)],
        "username": fake.user_name(),
        "password": fake.password(),
        "education": education[fake.random_int(0, 2)],
    }
    # send request to api
    response = requests.post(BASE_URL + "/register", json=fake_json)
    # print response
    print(response.status_code)
    print(response.json())



