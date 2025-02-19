import hashlib
import os
import base64
from flask import Flask, request, jsonify, render_template, send_file
from flask_cors import CORS
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
import paramiko  # Для создания OpenSSH ключей

app = Flask(__name__)
CORS(app)

app.config['MAX_CONTENT_LENGTH'] = 100 * 1024 * 1024  # 100MB

# Функция вычисления SHA-256 хэша файла
def calculate_file_hash(filepath):
    sha256_hash = hashlib.sha256()
    try:
        with open(filepath, "rb") as file:
            for byte_block in iter(lambda: file.read(4096), b""):
                sha256_hash.update(byte_block)
        return sha256_hash.hexdigest()
    except FileNotFoundError:
        return "Файл не найден"
    except Exception as e:
        return f"Ошибка: {str(e)}"

# Функция шифрования файла с использованием AES-GCM
def encrypt_file(filepath, key):
    try:
        key = hashlib.sha256(key.encode()).digest()  # Генерация 32-байтового ключа
        cipher = AES.new(key, AES.MODE_GCM)
        with open(filepath, "rb") as f:
            plaintext = f.read()
        ciphertext, tag = cipher.encrypt_and_digest(plaintext)
        encrypted_data = cipher.nonce + tag + ciphertext
        return encrypted_data
    except Exception as e:
        return f"Ошибка шифрования: {str(e)}"

# Функция расшифровки файла
def decrypt_file(filepath, key):
    try:
        key = hashlib.sha256(key.encode()).digest()
        with open(filepath, "rb") as f:
            encrypted_data = f.read()
        nonce, tag, ciphertext = encrypted_data[:16], encrypted_data[16:32], encrypted_data[32:]
        cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
        decrypted_data = cipher.decrypt_and_verify(ciphertext, tag)
        return decrypted_data
    except Exception as e:
        return f"Ошибка расшифровки: {str(e)}"

# Функция создания OpenSSH ключа
def generate_ssh_key(random_data):
    try:
        # Используем случайные данные для генерации ключа
        key = paramiko.RSAKey.generate(2048, random_data.encode())
        private_key = key.export_key("PEM")
        public_key = f"{key.get_name()} {key.get_base64()} generated-key"
        return private_key, public_key
    except Exception as e:
        return f"Ошибка генерации ключа: {str(e)}"

@app.route('/')
def home():
    return render_template('index.html')

@app.route('/hash-file', methods=['POST'])
def hash_file():
    if 'file' not in request.files:
        return jsonify({"message": "Файл не был загружен!"}), 400
    file = request.files['file']
    if file.filename == '':
        return jsonify({"message": "Файл не выбран!"}), 400
    file_path = os.path.join("uploads", file.filename)
    file.save(file_path)
    file_hash = calculate_file_hash(file_path)
    os.remove(file_path)

    # Сохраняем хэш в файл с расширением .txt (только хэш, без лишнего текста)
    hash_file_path = os.path.join("uploads", f"{file.filename[:100]}_hash.txt")
    with open(hash_file_path, "w") as f:
        f.write(file_hash)  # Только хэш, без лишнего текста

    # Отправляем файл с хэшем клиенту для скачивания
    return send_file(hash_file_path, as_attachment=True, download_name=f"{file.filename[:100]}_hash.txt")

@app.route('/encrypt-file', methods=['POST'])
def encrypt_endpoint():
    if 'file' not in request.files or 'key' not in request.form:
        return jsonify({"message": "Необходимы файл и ключ!"}), 400
    file = request.files['file']
    key = request.form['key']
    file_path = os.path.join("uploads", file.filename)
    file.save(file_path)
    encrypted_data = encrypt_file(file_path, key)
    os.remove(file_path)

    if isinstance(encrypted_data, str):  # Если произошла ошибка
        return jsonify({"message": encrypted_data}), 500

    # Сохраняем зашифрованные данные в файл с расширением .enc
    encrypted_file_path = os.path.join("uploads", f"{file.filename}.enc")
    with open(encrypted_file_path, "wb") as f:
        f.write(encrypted_data)

    # Отправляем файл клиенту для скачивания
    return send_file(encrypted_file_path, as_attachment=True, download_name=f"{file.filename}.enc")

@app.route('/decrypt-file', methods=['POST'])
def decrypt_endpoint():
    if 'file' not in request.files or 'key' not in request.form:
        return jsonify({"message": "Необходимы файл и ключ!"}), 400
    file = request.files['file']
    key = request.form['key']
    file_path = os.path.join("uploads", file.filename)
    file.save(file_path)
    decrypted_data = decrypt_file(file_path, key)
    os.remove(file_path)

    if isinstance(decrypted_data, str):  # Если произошла ошибка
        return jsonify({"message": decrypted_data}), 500

    # Восстанавливаем оригинальное имя файла (убираем .enc)
    original_filename = file.filename.replace(".enc", "")
    decrypted_file_path = os.path.join("uploads", original_filename)
    with open(decrypted_file_path, "wb") as f:
        f.write(decrypted_data)

    # Отправляем файл клиенту для скачивания
    return send_file(decrypted_file_path, as_attachment=True, download_name=original_filename)

@app.route('/generate-ssh-key', methods=['POST'])
def generate_ssh_key_endpoint():
    data = request.get_json()
    if 'random_data' not in data:
        return jsonify({"message": "Необходимы случайные данные!"}), 400
    random_data = data['random_data']
    private_key, public_key = generate_ssh_key(random_data)
    return jsonify({"private_key": private_key.decode(), "public_key": public_key})

if __name__ == '__main__':
    os.makedirs("uploads", exist_ok=True)
    app.run(host='0.0.0.0', port=5000, debug=True)