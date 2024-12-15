import os
import tkinter as tk
import random
from tkinter import Tk, Button, Label, Entry, filedialog, messagebox
from PIL import Image, ImageTk 
from tkinterdnd2 import DND_FILES, TkinterDnD


def get_seeded_random(seed):
    """Генерирует seed."""
    return random.Random(seed)

def encrypt_image(input_image_path, output_image_path, seed):
    """Шифрация изображения."""
    image = Image.open(input_image_path)
    width, height = image.size
    
    pixels = list(image.getdata())
    random_gen = get_seeded_random(seed)

    indices = list(range(len(pixels)))
    random_gen.shuffle(indices)

    encrypted_pixels = [pixels[i] for i in indices]

    encrypted_image = Image.new(image.mode, (width, height))
    encrypted_image.putdata(encrypted_pixels)
    encrypted_image.save(output_image_path)
    return True

def decrypt_image(input_image_path, output_image_path, seed):
    """Расшифровка изображения."""
    image = Image.open(input_image_path)
    width, height = image.size
    
    encrypted_pixels = list(image.getdata())
    random_gen = get_seeded_random(seed)

    indices = list(range(len(encrypted_pixels)))
    random_gen.shuffle(indices)

    decrypted_pixels = [None] * len(encrypted_pixels)

    for original_index, shuffled_index in enumerate(indices):
        decrypted_pixels[shuffled_index] = encrypted_pixels[original_index]

    decrypted_image = Image.new(image.mode, (width, height))
    decrypted_image.putdata(decrypted_pixels)
    decrypted_image.save(output_image_path)
    return True

def load_image(path):
    global photo, image_label
    image = Image.open(path)
    
    # Изменяем размер изображения
    max_size = (300, 300)  # Максимальный размер (ширина, высота)
    image.thumbnail(max_size)  # Изменяем размер с сохранением пропорций
    
    photo = ImageTk.PhotoImage(image)
    
    # Обновляем или создаем Label для отображения изображения
    if 'image_label' not in globals():
        image_label = tk.Label(root)
        image_label.pack()
    
    #input_drop_image.config("")
    image_label.config(image=photo)  # Обновляем изображение в Label
    image_label.image = photo  # Сохраняем ссылку на изображение


def select_input_image():
    """Выбор изображения."""
    global image_path
    image_path = filedialog.askopenfilename(title="Выберите изображение")
    input_image_label.config(text=image_path)
    if image_path:
        load_image(image_path)

def select_output_image():
    """Выбор для сохранения результата."""
    global output_image_path
    output_image_path = filedialog.asksaveasfilename(defaultextension=".png", filetypes=[("PNG files", "*.png"),("JPEG files", "*.jpg;*.jpeg"),("All files", "*.*")], title="Сохранить как")
    output_image_label.config(text=output_image_path)

def encrypt():
    input_image_path = input_image_label.cget("text")
    output_image_path = output_image_label.cget("text")
    seed = seed_entry.get()

    if not input_image_path or not output_image_path:
        messagebox.showerror("Ошибка", "Пожалуйста, выберите изображение или путь для сохранения результата.")
        return

    if encrypt_image(input_image_path, output_image_path, seed):
        messagebox.showinfo("Успех!", "Изображение успешно зашифровано!")

def decrypt():
    input_image_path = input_image_label.cget("text")
    output_image_path = output_image_label.cget("text")
    seed = seed_entry.get()

    if not input_image_path or not output_image_path:
        messagebox.showerror("Ошибка", "Пожалуйста, выберите изображение или путь для сохранения результата.")
        return

    if decrypt_image(input_image_path, output_image_path, seed):
        messagebox.showinfo("Успех!", "Изображение успешно дешифровано!")


def drop(event):
    """Обработка перетаскивания изображения."""
    file_path = event.data
    
    if os.path.isfile(file_path) and file_path.lower().endswith(('.png', '.jpg', '.jpeg')):
        load_image(file_path)
        input_image_label.config(text=file_path)

# Создаем основное окно
root = TkinterDnD.Tk()
root.title("Image Encryption Tool")

Label(root, text="Выберите изображение для шифрации/дешифрации:").pack(pady=5)
input_drop_image = Label(root, text="Перетащите изображение сюда")
input_drop_image.pack(pady=5)
input_image_label = Label(root, text="Изображение не было выбрано")
input_image_label.pack(pady=5)

image_label = tk.Label(root)
image_label.pack()

Button(root, text="Выбрать", command=select_input_image).pack(pady=5)

Label(root, text="Путь для сохранения:").pack(pady=5)
output_image_label = Label(root, text="Путь для сохранения не выбран")
output_image_label.pack(pady=5)

Button(root, text="Сохранить", command=select_output_image).pack(pady=5)

Label(root, text="Введите ключ:").pack(pady=5)
seed_entry = Entry(root)
seed_entry.pack(pady=5)

# Настройка перетаскивания
root.drop_target_register(DND_FILES)
root.dnd_bind('<<Drop>>', drop)


Button(root, text="Зашифровать изображение", command=encrypt).pack(pady=5)
Button(root, text="Дешифровать изображение", command=decrypt).pack(pady=5)

root.mainloop()

#testtseststesdt
