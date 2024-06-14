import tkinter as tk
from tkinter import ttk

def lfsr_step(lfsr_value, feedback_value):
    lsb = lfsr_value & 1  # Compute the least significant bit (LSB) of the current LFSR value
    lfsr_value >>= 1  # Shift the LFSR value to the right by one bit
    if lsb:  # If the LSB was 1, XOR the LFSR value with the feedback value
        lfsr_value ^= feedback_value
    return lfsr_value  # Return the new LFSR value

def Crypt(data: bytes, initialValue: int, steps: int, feedback_value: int) -> bytes:
    lfsr_value = initialValue  
    encrypted_data = bytearray()  

    for byte in data: 
        for _ in range(steps):  # Step the LFSR 'steps' times to produce the next key byte
            lfsr_value = lfsr_step(lfsr_value, feedback_value)
        key_byte = lfsr_value & 0xFF  # Extract the lowest byte of the current LFSR value as the key byte
        encrypted_data.append(byte ^ key_byte)  # XOR the current data byte with the key byte and append to result
    return bytes(encrypted_data) 

def format_bytes_as_hex(byte_data):
    return ''.join(f'\\x{byte:02X}' for byte in byte_data)  # Convert each byte to a hex string and join them

def validate_initial_value(input_str):
    if not input_str.startswith('0x') or not all(c in '0123456789abcdefABCDEF' for c in input_str[2:]):
        raise ValueError("Initial value must be a hexadecimal number (e.g., 0x12345678).")
    return int(input_str, 16)

def validate_feedback_value(input_str):
    if not input_str.startswith('0x') or not all(c in '0123456789abcdefABCDEF' for c in input_str[2:]):
        raise ValueError("Feedback value must be a hexadecimal number (e.g., 0x87654321).")
    return int(input_str, 16)

def validate_steps(input_str):
    try:
        steps = int(input_str)
        if steps <= 0:
            raise ValueError("Steps must be a positive integer.")
        return steps
    except ValueError:
        raise ValueError("Steps must be a positive integer.")

def process_data():
    error_label.config(text="")  # Clear any previous error message

    choice = choice_var.get()
    data_input = data_entry.get()
    initial_value_str = initial_value_entry.get()
    feedback_value_str = feedback_value_entry.get()
    steps_str = steps_entry.get()

    try:
        initialValue = validate_initial_value(initial_value_str)
        feedback_value = validate_feedback_value(feedback_value_str)
        steps = validate_steps(steps_str)

        if choice == 'encrypt':
            data = data_input.encode()
        else:
            try:
                data = bytes.fromhex(data_input.replace("\\x", ""))
            except ValueError:
                raise ValueError("Data for decryption must be in the format \\x.. where .. are hexadecimal digits.")

        result = Crypt(data, initialValue, steps, feedback_value)

        result_display.config(state=tk.NORMAL)  # Enable editing the result_display
        if choice == 'encrypt':
            result_display.delete('1.0', tk.END)  # Clear previous content
            result_display.insert(tk.END, format_bytes_as_hex(result))
        else:
            try:
                result_display.delete('1.0', tk.END)  # Clear previous content
                result_display.insert(tk.END, result.decode())
            except UnicodeDecodeError:
                result_display.delete('1.0', tk.END)  # Clear previous content
                result_display.insert(tk.END, format_bytes_as_hex(result))
                error_label.config(text="Error: Decryption resulted in non-text data.")
                return

        result_display.config(state=tk.DISABLED)  # Disable editing the result_display
    except Exception as e:
        error_label.config(text=f"Error: {e}")

root = tk.Tk()
root.title("LFSR Encrypt/Decrypt Tool")

mainframe = ttk.Frame(root, padding="10")
mainframe.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))

ttk.Label(mainframe, text="Data:").grid(row=0, column=0, sticky=tk.W)
data_entry = ttk.Entry(mainframe, width=50)
data_entry.grid(row=0, column=1, sticky=(tk.W, tk.E))

ttk.Label(mainframe, text="Initial Value (hex, e.g., 0x12345678):").grid(row=1, column=0, sticky=tk.W)
initial_value_entry = ttk.Entry(mainframe)
initial_value_entry.grid(row=1, column=1, sticky=(tk.W, tk.E))

ttk.Label(mainframe, text="Feedback Value (hex, e.g., 0x87654321):").grid(row=2, column=0, sticky=tk.W)
feedback_value_entry = ttk.Entry(mainframe)
feedback_value_entry.grid(row=2, column=1, sticky=(tk.W, tk.E))

ttk.Label(mainframe, text="Steps:").grid(row=3, column=0, sticky=tk.W)
steps_entry = ttk.Entry(mainframe)
steps_entry.grid(row=3, column=1, sticky=(tk.W, tk.E))

choice_var = tk.StringVar()
ttk.Radiobutton(mainframe, text="Encrypt", variable=choice_var, value="encrypt").grid(row=4, column=0, sticky=tk.W)
ttk.Radiobutton(mainframe, text="Decrypt", variable=choice_var, value="decrypt").grid(row=4, column=1, sticky=tk.W)
choice_var.set("encrypt")

ttk.Button(mainframe, text="Process", command=process_data).grid(row=5, column=0, columnspan=2)

ttk.Label(mainframe, text="Result:").grid(row=6, column=0, sticky=tk.W)
result_display = tk.Text(mainframe, height=10, width=50)
result_display.grid(row=7, column=0, columnspan=2, sticky=(tk.W, tk.E))
result_display.config(state=tk.DISABLED)  # Initially disable editing

error_label = ttk.Label(mainframe, text="", foreground="red")
error_label.grid(row=8, column=0, columnspan=2, sticky=tk.W)

for child in mainframe.winfo_children():
    child.grid_configure(padx=5, pady=5)

root.mainloop()
