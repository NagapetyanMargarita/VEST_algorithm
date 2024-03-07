# This is a sample Python script.
import hashlib

import keyboard as keyboard
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives import hmac
import os
import tkinter as tk
from tkinter import messagebox


# Функция для генерации ключа
def generate_key():
    # Генерируем случайную соль
    salt = os.urandom(16)

    # Создаем объект PBKDF2HMAC для генерации ключа
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )

    # Генерируем ключ
    key = kdf.derive(b"password")

    return key


# Функция для хеширования данных
def hash_data(data, key):
    # Создаем объект HMAC с использованием ключа
    h = hmac.HMAC(key, hashes.SHA256(), backend=default_backend())

    # Обновляем HMAC с данными
    h.update(data)

    # Получаем хеш
    digest = h.finalize()

    return digest


# Функция для шифрования данных с аутентификацией
def encrypt_data(data, key):
    # Генерируем случайный инициализационный вектор
    iv = os.urandom(16)

    # Создаем объект шифра AES в режиме CBC
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())

    # Создаем паддинг PKCS7
    padder = padding.PKCS7(128).padder()

    # Применяем паддинг к данным
    padded_data = padder.update(data) + padder.finalize()

    # Создаем шифратор
    encryptor = cipher.encryptor()

    # Шифруем данные
    ciphertext = encryptor.update(padded_data) + encryptor.finalize()

    # Создаем объект HMAC с использованием ключа
    h = hmac.HMAC(key, hashes.SHA256(), backend=default_backend())

    # Обновляем HMAC с зашифрованными данными
    h.update(ciphertext)

    # Получаем аутентификационный тег
    tag = h.finalize()


    return ciphertext, iv, tag


# Функция для расшифровки данных с аутентификацией
def decrypt_data(ciphertext, iv, tag, key):
    # Создаем объект шифра AES в режиме CBC
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())

    # Создаем дешифратор
    decryptor = cipher.decryptor()

    # Расшифровываем данные
    padded_data = decryptor.update(ciphertext) + decryptor.finalize()

    # Создаем анпаддинг PKCS7
    unpadder = padding.PKCS7(128).unpadder()

    # Удаляем паддинг из данных
    data = unpadder.update(padded_data) + unpadder.finalize()

    # Создаем объект HMAC с использованием ключа
    h = hmac.HMAC(key, hashes.SHA256(), backend=default_backend())

    # Обновляем HMAC с зашифрованными данными
    h.update(ciphertext)

    try:
        # Проверяем аутентификационный тег
        h.verify(tag)
        return data
    except InvalidSignature:
        print("Аутентификация не удалась.")
        return None

def encrypt_button_click():
    data = input_text.get().encode("utf-8")
    key = generate_key()
    key_str = key.hex()

    hashed_data = hash_data(data, key)
    hashed_data_str = hashed_data.hex()

    ciphertext, iv, tag = encrypt_data(data, key)
    ciphertext_str = ciphertext.hex()
    tag_str = tag.hex()
    iv_str = iv.hex()

    output_text.delete("1.0", tk.END)
    output_text.insert(tk.END, "Зашифрованные данные: " + ciphertext_str + "\n")
    output_text.insert(tk.END, "Вектор: " + iv_str + "\n")
    output_text.insert(tk.END, "Аутентификационный тег: " + tag_str + "\n")
    output_text.insert(tk.END, "Ключ: " + key_str + "\n")

def decrypt_button_click():
    ciphertext = bytes.fromhex(decrypted_text.get("1.0", tk.END).strip())
    iv = bytes.fromhex(iv_text.get("1.0", tk.END).strip())
    tag = bytes.fromhex(tag_text.get("1.0", tk.END).strip())
    key = bytes.fromhex(key_text.get("1.0", tk.END).strip())

    decrypted_data = decrypt_data(ciphertext, iv, tag, key)
    result_text.delete("1.0", tk.END)
    if decrypted_data is not None:
        decrypted_data_str = decrypted_data.decode()  # Преобразование из байтовой строки в обычную строку
        result_text.insert(tk.END, decrypted_data_str + "\n")


def copy_text():
    selected_text = output_text.selection_get()
    if selected_text:
        window.clipboard_clear()
        window.clipboard_append(selected_text)
    else:
        messagebox.showwarning("Ничего не выбрано", "Пожалуйста, выберите текст для копирования.")

def paste_text():
    # Получите текст из буфера обмена
    text = window.clipboard_get()
    # Определите текущее активное поле ввода
    active_field = window.focus_get()
    # Вставьте текст в выбранное поле
    if active_field == iv_text:
        iv_text.insert(tk.END, text)
    elif active_field == tag_text:
        tag_text.insert(tk.END, text)
    elif active_field == key_text:
        key_text.insert(tk.END, text)
    elif active_field == decrypted_text:
        decrypted_text.insert(tk.END, text)



window = tk.Tk()
window.title("Алгоритм Vest")
window.geometry("1000x780")  # Ширина x Высота

keyboard.add_hotkey('ctrl+c', copy_text)
keyboard.add_hotkey('ctrl+v', paste_text)
# Создание фрейма с установленным цветом фона и высотой 1 пиксель
line_frame = tk.Frame(window, bg="black", height=2)

# Размещение фрейма с линией после поля output_text
line_frame.pack(fill="x", padx=50, pady=25)

# Создание пустой метки с черной рамкой
line_label = tk.Label(line_frame, text="Шифрование сообщений", bg="pink", relief="sunken")

# Размещение метки
line_label.pack(fill="x")
# Поле ввода текста
input_text = tk.Entry(window, width=100)
input_text.pack(pady=15, padx=20)

# Кнопка для запуска шифрования
encrypt_button = tk.Button(window, text="Зашифровать", command=encrypt_button_click, bg="pink")
encrypt_button.pack()

# Поле вывода результатов
output_text = tk.Text(window, height=9, width=200)
output_text.pack(padx=50, pady=20)

# Создание фрейма с установленным цветом фона и высотой 1 пиксель
line_frame = tk.Frame(window, bg="black", height=2)

# Размещение фрейма с линией после поля output_text
line_frame.pack(fill="x", padx=50, pady=25)

# Создание пустой метки с черной рамкой
line_label = tk.Label(line_frame, text="Расшифровка сообщений", bg="yellow",relief="sunken")

# Размещение метки
line_label.pack(fill="x")

# Поле ввода зашифрованного сообщения
# Надпись
label_text = "Введите зашифрованное сообщение"
label = tk.Label(window, text=label_text)
label.pack(padx=50)

decrypted_text = tk.Text(window, height=2, width=200)
decrypted_text.pack(padx=50)

label_text = "Введите Инициализованный вектор"
label = tk.Label(window, text=label_text)
label.pack()

# Поле ввода инициализованного вектора
iv_text = tk.Text(window, height=2, width=200)
iv_text.pack(padx=50)

label_text = "Введите Аутентификационный тег"
label = tk.Label(window, text=label_text)
label.pack()

# Поле ввода аутентификационного тега
tag_text = tk.Text(window, height=2, width=200)
tag_text.pack(padx=50)

label_text = "Введите ключ"
label = tk.Label(window, text=label_text)
label.pack()

# Поле ввода ключа
key_text = tk.Text(window, height=2, width=200)
key_text.pack(padx=50)


label_text = "Расшифрованное сообщение"
label = tk.Label(window, text=label_text)
label.pack()

# Поле ввода ключа
result_text = tk.Text(window, height=2, width=200)
result_text.pack(pady=10, padx=50)

# Кнопка для запуска шифрования
decrypt_button = tk.Button(window, text="Расшифровать", command=decrypt_button_click, bg="yellow")
decrypt_button.pack()

"""# Кнопка для запуска шифрования
copy_button = tk.Button(window, text="Скопировать", command=copy_text)
copy_button.pack()

paste_button = tk.Button(window, text="Вставить", command=paste_text)
paste_button.pack()"""

# Запуск главного цикла обработки событий
window.mainloop()

