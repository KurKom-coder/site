import hashlib
import os
from flask import Flask, request, jsonify, render_template
from flask_cors import CORS

app = Flask(__name__)
CORS(app)

# Устанавливаем максимальный размер файла (100 MB)
app.config['MAX_CONTENT_LENGTH'] = 100 * 1024 * 1024  # 100MB

def calculate_file_hash(filepath):
    """Вычисляет хэш файла с использованием SHA-256."""
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

@app.route('/')
def home():
    """Отображает главную страницу."""
    return render_template('index.html')

@app.route('/process-file', methods=['POST'])
def process_file():
    """Обрабатывает загруженный файл."""
    if 'file' not in request.files:
        return jsonify({"message": "Файл не был загружен!"})
    
    file = request.files['file']
    if file.filename == '':
        return jsonify({"message": "Файл не выбран!"})
    
    # Проверяем размер файла
    file.seek(0, os.SEEK_END)
    file_size = file.tell()
    file.seek(0, os.SEEK_SET)
    if file_size >= 100 * 1024 * 1024:
        return jsonify({"message": "Ошибка: Файл не должен быть больше 100MB!"}), 400
    
    # Сохраняем файл временно
    upload_dir = "uploads"
    os.makedirs(upload_dir, exist_ok=True)
    file_path = os.path.join(upload_dir, file.filename)
    file.save(file_path)
    
    # Вычисляем хэш
    file_hash = calculate_file_hash(file_path)
    print(f"Хэш файла {file.filename}: {file_hash}")  # Логируем хэш
    
    # Удаляем файл после обработки
    try:
        os.remove(file_path)
    except Exception as e:
        return jsonify({"message": f"Ошибка при удалении файла: {str(e)}"})
    
    return jsonify({"message": f"Файл '{file.filename}' загружен и удален. Хэш: {file_hash}"})

@app.errorhandler(413)
def request_entity_too_large(error):
    """Обрабатывает ошибку слишком большого файла."""
    return jsonify({"message": "Ошибка: Файл не должен быть больше 100MB!"}), 413

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)