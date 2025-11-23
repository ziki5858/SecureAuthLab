import requests

url = "http://127.0.0.1:5000/login"

payload = {
    "username": "user01",
    "password": "vxownw"  # מהקובץ generated_passwords.txt
}

res = requests.post(url, json=payload)
print(res.text)
