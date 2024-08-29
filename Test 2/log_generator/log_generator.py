import time
import random
import requests
import logging
import socket
import json
from faker import Faker

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(message)s')
logger = logging.getLogger(__name__)

fake = Faker()

def send_log(message):
    log_entry = json.dumps({"message": message})
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.connect(("logstash", 5044))
        s.sendall(log_entry.encode() + b'\n')

def generate_normal_traffic():
    endpoints = ['/', '/products', '/login']
    endpoint = random.choice(endpoints)

    if endpoint == '/login':
        data = {'username': fake.user_name(), 'password': fake.password()}
        response = requests.post(f'http://web:5000{endpoint}', json=data)
    else:
        response = requests.get(f'http://web:5000{endpoint}')

    send_log(
        f"Normal traffic - Method: {response.request.method}, URL: {response.url}, Status: {response.status_code}")


def generate_attack_traffic():
    attack_types = ['sql_injection', 'brute_force', 'xss']
    attack = random.choice(attack_types)

    if attack == 'sql_injection':
        sql_payloads = [
            "' OR '1'='1",  # Classic SQL injection
            "' UNION SELECT username, password FROM users --",  # Union-based SQL injection
            "'; DROP TABLE users; --",  # SQL Drop injection
        ]
        payload = random.choice(sql_payloads)
        response = requests.get(f'http://web:5000/products?id={payload}')
        send_log(f"Attack traffic - SQL Injection attempt: {response.url}")

    elif attack == 'brute_force':
        for _ in range(5):  # Simulate 5 rapid login attempts
            data = {'username': 'admin', 'password': fake.password()}
            response = requests.post('http://web:5000/login', json=data)
            send_log(f"Attack traffic - Brute force attempt: {data['username']} with password {data['password']}")

    elif attack == 'xss':
        xss_payloads = [
            "<script>alert('XSS')</script>",
            '"><img src=x onerror=alert(1)>',  # Image tag-based XSS
            "<svg/onload=alert(1)>",  # SVG-based XSS
        ]
        payload = random.choice(xss_payloads)
        response = requests.get(f'http://web:5000/products?search={payload}')
        send_log(f"Attack traffic - XSS attempt: {response.url}")

    elif attack == 'ddos':
        for _ in range(100):  # Simulate 100 requests in a short time
            response = requests.get('http://web:5000/products')
            send_log(f"Attack traffic - DDoS attempt: {response.url}")
    
    elif attack == 'path_traversal':
        payload = "../../etc/passwd"  # Simulate accessing restricted file
        response = requests.get(f'http://web:5000/files?file={payload}')
        send_log(f"Attack traffic - Path traversal attempt: {response.url}")
    
    elif attack == 'directory_listing':
        response = requests.get('http://web:5000/admin/')
        send_log(f"Attack traffic - Directory listing attempt: {response.url}")
    
    elif attack == 'csrf':
        fake_session_token = fake.sha256()  # Generate a fake session token
        headers = {
            'X-CSRF-Token': fake_session_token
        }
        response = requests.post('http://web:5000/profile', json={'name': fake.name()}, headers=headers)
        send_log(f"Attack traffic - CSRF attempt with token: {fake_session_token}")
    
    elif attack == 'ldap_injection':
        ldap_payloads = [
            "admin*)(objectclass=*)",  # Basic LDAP Injection
            "admin*|(&(objectclass=*))",  # LDAP Filter bypass
        ]
        payload = random.choice(ldap_payloads)
        response = requests.get(f'http://web:5000/users?search={payload}')
        send_log(f"Attack traffic - LDAP Injection attempt: {response.url}")


if __name__ == '__main__':
    while True:
        if random.random() < 0.9:
            generate_normal_traffic()
        else:
            generate_attack_traffic()
        time.sleep(random.uniform(0.1, 2))
