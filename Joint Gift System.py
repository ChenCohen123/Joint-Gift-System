import tkinter as tk
from tkinter import messagebox, scrolledtext
import random

# Initialize the main window
root = tk.Tk()
root.title("Joint Gift System")
root.geometry("1200x700")  # Increase the initial size of the main window

# Styling
modern_font = ("Arial", 10, "bold")  # Adjusted font size
button_font = ("Arial", 8, "bold")  # Adjusted font size
input_background = "#F7F9F9"
button_active_color = "#D5E8D4"
button_background = "#A3D2CA"
text_area_background = "#000000"  # Set background to black
text_area_foreground = "#FFFFFF"  # Set font color to white

# Configure the root background
root.configure(bg=input_background)

# Create a frame for user inputs
input_frame = tk.Frame(root, bg=input_background)
input_frame.pack(side=tk.LEFT, padx=20, pady=20, fill="y", expand=True)

# Create a label to display instructions
instruction_label = tk.Label(input_frame, text="Welcome to the gift system,\nplease enter your budget (up to NIS 3)",
                             font=modern_font, bg=input_background, justify=tk.LEFT)
instruction_label.pack()

# Create frames for User 1, User 2, User 3 logs
user_frames = []
user_logs = []

for i in range(3):
    frame = tk.Frame(root, bg=input_background)
    frame.pack(side=tk.LEFT, padx=10, pady=10, fill="both",
               expand=True)  # Adjust fill to both to ensure size consistency
    label = tk.Label(frame, text=f"User {i + 1}", font=modern_font, bg=input_background)
    label.pack()
    log = scrolledtext.ScrolledText(frame, font=modern_font, bg=text_area_background, fg=text_area_foreground, width=50,
                                    height=25, wrap=tk.WORD, spacing3=10)  # Adjusted size, wrap to WORD, added spacing
    log.pack()
    user_frames.append(frame)
    user_logs.append(log)

# Variables to hold the user inputs
user_inputs = [None, None, None]
user_initial_bits = [None, None, None]
message_counter = 1
simulation_active = False
user_bits_to_send = None

# RSA keys for each user
rsa_keys = [
    {'N': 1147, 'e': 17, 'd': 953},
    {'N': 1271, 'e': 11, 'd': 1091},
    {'N': 1073, 'e': 29, 'd': 869}
]

user_split_bits = [[[None, None, None] for _ in range(4)] for _ in range(3)]
encrypted_messages1 = [None, None, None]
encrypted_messages2 = [None, None, None]
encrypted_messages3 = [None, None, None]

# Function to log messages to a specific user's log
def log_message(user_index, message):
    global message_counter
    user_logs[user_index].insert(tk.END, f"{message_counter}. {message}\n\n")  # Added double newline for spacing
    user_logs[user_index].yview(tk.END)
    message_counter += 1

# Function to perform RSA encryption
def rsa_encrypt(receiver_index, plaintext):
    key = rsa_keys[receiver_index]
    N, e = key['N'], key['e']
    r = random.randint(0, N - 1)  # Generate a random number in the range [0, N-1]
    r_enc = pow(r, e, N)
    encrypted_part = plaintext ^ (r & 0b1111)
    encrypted_message = f"{r_enc:04},{encrypted_part:04}"
    return encrypted_message, r, r_enc, encrypted_part

# Function to perform RSA decryption
def rsa_decrypt(receiver_index, encrypted_message):
    key = rsa_keys[receiver_index]
    N, d = key['N'], key['d']
    r_enc_str, encrypted_part_str = encrypted_message.split(',')
    r_enc = int(r_enc_str)
    encrypted_part = int(encrypted_part_str)
    r = pow(r_enc, d, N)
    plaintext = encrypted_part ^ (r & 0b1111)
    return plaintext, r, r_enc, encrypted_part

# Logical function to send a message
def send_message_logic(sender, receiver, message):
    encrypted_message, r, r_enc, encrypted_part = rsa_encrypt(receiver, message)
    log_message(sender,
                f" Encrypting message for User {receiver + 1}:\n 1. Generate random number (r): {r}\n 2. Encrypt random number:\n    r^{rsa_keys[receiver]['e']} % {rsa_keys[receiver]['N']} = {r_enc}\n 3. XOR plaintext with r & 0b1111:\n    {message} XOR ({r} & 0b1111) = {encrypted_part}\n 4. Form encrypted message: {encrypted_message}")
    log_message(sender, f"Sent encrypted message to User {receiver + 1}: {encrypted_message}")
    log_message(receiver, f"Received encrypted message from User {sender + 1}: {encrypted_message}")
    return encrypted_message, encrypted_part

# Logical function to receive and decode a message
def receive_message_logic(receiver, encrypted_message):
    decrypted_message, r, r_enc, encrypted_part = rsa_decrypt(receiver, encrypted_message)
    log_message(receiver,
                f" Decrypting message:\n 1. Decrypting random number:\n    r_enc^{rsa_keys[receiver]['d']} % {rsa_keys[receiver]['N']} = {r}\n 2. XOR with encrypted part:\n    {encrypted_part} XOR ({r} & 0b1111) = {decrypted_message}")
    return decrypted_message

# Function to handle value entry
def enter_value(user_index):
    def submit():
        try:
            value = int(entry.get())
            if 0 <= value <= 3:
                user_inputs[user_index] = value
                log_message(user_index, f"Entered: {value}")
                entry_window.destroy()
            else:
                messagebox.showerror("Invalid Input", "Please enter an integer value between 0 and 3.")
        except ValueError:
            messagebox.showerror("Invalid Input", "Please enter an integer value.")

    # Create the entry window
    entry_window = tk.Toplevel(root, bg=input_background)
    entry_window.title(f"User {user_index + 1}")
    entry_window.geometry("300x150")  # Size of the entry window
    # Position the entry window relative to the main window
    window_x = root.winfo_x() + 200
    window_y = root.winfo_y() + 100 + (100 * user_index)
    entry_window.geometry(f"+{window_x}+{window_y}")

    tk.Label(entry_window, text="Enter your budget:", font=modern_font, bg=input_background).pack(pady=10)
    entry = tk.Entry(entry_window, font=modern_font)
    entry.pack(pady=10)
    submit_button = tk.Button(entry_window, text="Enter Value", command=submit,
                              font=button_font, activebackground=button_active_color, bg=button_background,
                              relief="flat")
    submit_button.pack(pady=10)

# Function to reset the simulation
def reset_simulation():
    global message_counter, user3_initial_value, user3_accumulated_value, user_inputs, user_initial_bits, simulation_active, user_split_bits, encrypted_messages1, encrypted_messages2, encrypted_messages3, user_bits_to_send

    # Reset all global variables to their initial state
    user_inputs = [None, None, None]
    user_initial_bits = [None, None, None]
    user_split_bits = [[[None, None, None] for _ in range(4)] for _ in range(3)]
    encrypted_messages1 = [None, None, None]
    encrypted_messages2 = [None, None, None]
    encrypted_messages3 = [None, None, None]
    user_bits_to_send = None
    message_counter = 1
    simulation_active = False

    # Clear the log windows
    for log in user_logs:
        log.delete(1.0, tk.END)

    # Update button states
    start_button.config(state=tk.NORMAL)
    reset_button.pack_forget()

# Button to reset the simulation
reset_button = tk.Button(input_frame, text="Reset Simulation", command=reset_simulation,
                         font=button_font, activebackground=button_active_color, bg="#F76C6C", relief="flat")

# Hide the reset button initially
reset_button.pack_forget()

# Function to generate secure bits
def generate_secure_bits(bit, n, *output_bits):
    if len(output_bits) != 3:
        raise ValueError("Function requires exactly 3 output variables")
    random_bits = [random.randint(0, 1) for _ in range(n - 1)]
    nth_bit = bit
    for b in random_bits:
        nth_bit ^= b
    random_bits.append(nth_bit)
    random.shuffle(random_bits)
    for i in range(3):
        output_bits[i][0] = random_bits[i]
    return output_bits

# Function to perform secure bit splitting and logging
def split_and_log_bits(user_index, bits):
    split_bits = []
    for bit in bits[::-1]:  # Iterate in reverse to go from LSB to MSB
        part1, part2, part3 = [None], [None], [None]
        generate_secure_bits(bit, 3, part1, part2, part3)
        split_bits.append([part1[0], part2[0], part3[0]])
    for i, (bit1, bit2, bit3) in enumerate(split_bits):
        log_message(user_index, f"Splitting bit {i} into ({bit1}, {bit2}, {bit3})")  # Correct order
    return split_bits

def prepare_bits_to_send():
    global user_split_bits, user_bits_to_send
    user_bits_to_send = [[[None, None, None] for _ in range(4)] for _ in range(3)]
    for user_index in range(3):
        for i in range(4):
            for j in range(3):
                user_bits_to_send[user_index][i][j] = user_split_bits[user_index][i][j]

def send_bits(user_index):
    global user_bits_to_send
    if user_index == 0:  # User 1
        bits_to_send_user_2 = []
        bits_to_send_user_3 = []
        for i in range(4):
            bits_to_send_user_2.append(user_bits_to_send[user_index][i][1])  # Send index 1 to User 2
            bits_to_send_user_3.append(user_bits_to_send[user_index][i][2])  # Send index 2 to User 3
        bits_string_user_2 = ''.join(map(str, bits_to_send_user_2))
        bits_string_user_3 = ''.join(map(str, bits_to_send_user_3))
        encrypted_message_user_2, _ = send_message_logic(user_index, 1, int(bits_string_user_2, 2))
        encrypted_message_user_3, _ = send_message_logic(user_index, 2, int(bits_string_user_3, 2))
        encrypted_messages2[0] = encrypted_message_user_2
        encrypted_messages3[0] = encrypted_message_user_3
        print(f"User {user_index + 1} sent bits: {bits_string_user_2} to User 2 and {bits_string_user_3} to User 3")
    elif user_index == 1:  # User 2
        bits_to_send_user_1 = []
        bits_to_send_user_3 = []
        for i in range(4):
            bits_to_send_user_1.append(user_bits_to_send[user_index][i][0])  # Send index 0 to User 1
            bits_to_send_user_3.append(user_bits_to_send[user_index][i][2])  # Send index 2 to User 3
        bits_string_user_1 = ''.join(map(str, bits_to_send_user_1))
        bits_string_user_3 = ''.join(map(str, bits_to_send_user_3))
        encrypted_message_user_1, _ = send_message_logic(user_index, 0, int(bits_string_user_1, 2))
        encrypted_message_user_3, _ = send_message_logic(user_index, 2, int(bits_string_user_3, 2))
        encrypted_messages1[1] = encrypted_message_user_1
        encrypted_messages3[1] = encrypted_message_user_3
        print(f"User {user_index + 1} sent bits: {bits_string_user_1} to User 1 and {bits_string_user_3} to User 3")
    elif user_index == 2:  # User 3
        bits_to_send_user_1 = []
        bits_to_send_user_2 = []
        for i in range(4):
            bits_to_send_user_1.append(user_bits_to_send[user_index][i][0])  # Send index 0 to User 1
            bits_to_send_user_2.append(user_bits_to_send[user_index][i][1])  # Send index 1 to User 2
        bits_string_user_1 = ''.join(map(str, bits_to_send_user_1))
        bits_string_user_2 = ''.join(map(str, bits_to_send_user_2))
        encrypted_message_user_1, _ = send_message_logic(user_index, 0, int(bits_string_user_1, 2))
        encrypted_message_user_2, _ = send_message_logic(user_index, 1, int(bits_string_user_2, 2))
        encrypted_messages1[2] = encrypted_message_user_1
        encrypted_messages2[2] = encrypted_message_user_2
        print(f"User {user_index + 1} sent bits: {bits_string_user_1} to User 1 and {bits_string_user_2} to User 2")

def receive_bits(user_index):
    global user_split_bits, encrypted_messages1, encrypted_messages2, encrypted_messages3
    if user_index == 0:  # User 1
        encrypted_message_user_2 = encrypted_messages1[1]
        encrypted_message_user_3 = encrypted_messages1[2]
        if encrypted_message_user_2:
            decrypted_bits_user_2 = receive_message_logic(user_index, encrypted_message_user_2)
            decrypted_bits_user_2 = format(decrypted_bits_user_2, '04b')  # Remove the reverse
            for i in range(4):
                user_split_bits[user_index][i][1] = int(decrypted_bits_user_2[i])
        if encrypted_message_user_3:
            decrypted_bits_user_3 = receive_message_logic(user_index, encrypted_message_user_3)
            decrypted_bits_user_3 = format(decrypted_bits_user_3, '04b')  # Remove the reverse
            for i in range(4):
                user_split_bits[user_index][i][2] = int(decrypted_bits_user_3[i])
    elif user_index == 1:  # User 2
        encrypted_message_user_1 = encrypted_messages2[0]
        encrypted_message_user_3 = encrypted_messages2[2]
        if encrypted_message_user_1:
            decrypted_bits_user_1 = receive_message_logic(user_index, encrypted_message_user_1)
            decrypted_bits_user_1 = format(decrypted_bits_user_1, '04b')  # Remove the reverse
            for i in range(4):
                user_split_bits[user_index][i][0] = int(decrypted_bits_user_1[i])
        if encrypted_message_user_3:
            decrypted_bits_user_3 = receive_message_logic(user_index, encrypted_message_user_3)
            decrypted_bits_user_3 = format(decrypted_bits_user_3, '04b')  # Remove the reverse
            for i in range(4):
                user_split_bits[user_index][i][2] = int(decrypted_bits_user_3[i])
    elif user_index == 2:  # User 3
        encrypted_message_user_1 = encrypted_messages3[0]
        encrypted_message_user_2 = encrypted_messages3[1]
        if encrypted_message_user_1:
            decrypted_bits_user_1 = receive_message_logic(user_index, encrypted_message_user_1)
            decrypted_bits_user_1 = format(decrypted_bits_user_1, '04b')  # Remove the reverse
            for i in range(4):
                user_split_bits[user_index][i][0] = int(decrypted_bits_user_1[i])
        if encrypted_message_user_2:
            decrypted_bits_user_2 = receive_message_logic(user_index, encrypted_message_user_2)
            decrypted_bits_user_2 = format(decrypted_bits_user_2, '04b')  # Remove the reverse
            for i in range(4):
                user_split_bits[user_index][i][1] = int(decrypted_bits_user_2[i])
        print(f"User {user_index + 1} sets its own bit {int(format(user_inputs[user_index], '04b')[i])} for position {i}")

# Function to calculate list as per user 1's values
def calculate(x, y):
    c = random.randint(0, 1)
    result = [
        c ^ (x ^ 0) & (y ^ 0),
        c ^ (x ^ 0) & (y ^ 1),
        c ^ (x ^ 1) & (y ^ 0),
        c ^ (x ^ 1) & (y ^ 1)
    ]
    return result, c

# Oblivious Transfer function
def oblivious_transfer(a1, y1, a2, y2, index1, index2):
    # User 1 creates list and draws c1
    user1list, c1 = calculate(a1, y1)
    log_message(index1, f"User {index1 + 1} generated list: {user1list} with c1: {c1}")

    # User 2 creates a list of 4 random values
    user2list = [random.randint(0, rsa_keys[index2]['N'] - 1) for _ in range(4)]
    user2input = user2list.copy()

    # Encrypt the specific cell based on a2 and y2
    if a2 == 0 and y2 == 0:
        user2list[0], r, r_enc, encrypted_part = rsa_encrypt(index1, user2list[0])
    elif a2 == 0 and y2 == 1:
        user2list[1], r, r_enc, encrypted_part = rsa_encrypt(index1, user2list[1])
    elif a2 == 1 and y2 == 0:
        user2list[2], r, r_enc, encrypted_part = rsa_encrypt(index1, user2list[2])
    elif a2 == 1 and y2 == 1:
        user2list[3], r, r_enc, encrypted_part = rsa_encrypt(index1, user2list[3])

    log_message(index2, f"User {index2 + 1} generated list: {user2list} with user2input: {user2input}")

    # Format user2list for decryption
    for i in range(4):
        if isinstance(user2list[i], int):
            user2list[i] = f"{user2list[i]:04},{user2list[i]:04}"

    log_message(index1, f"User {index1 + 1} received modified list: {user2list}")
    log_message(index2, f"User {index2 + 1} sent modified list: {user2list}")

    # User 1 decrypts the received list
    user2listCopyTo1 = user2list.copy()
    for i in range(4):
        decrypted, _, _, _ = rsa_decrypt(index1, user2listCopyTo1[i])
        user2listCopyTo1[i] = decrypted & 0b1

    log_message(index1, f"User {index1 + 1} decrypted list to: {user2listCopyTo1}")

    # User 1 performs XOR with its original list
    for i in range(4):
        user2listCopyTo1[i] = user1list[i] ^ user2listCopyTo1[i]

    log_message(index1, f"User {index1 + 1} updated list after XOR: {user2listCopyTo1}")

    # User 1 sends the updated list to User 2
    log_message(index2, f"User {index2 + 1} received updated list: {user2listCopyTo1}")
    log_message(index1, f"User {index1 + 1} sent updated list: {user2listCopyTo1}")

    # User 2 calculates c2
    if a2 == 0 and y2 == 0:
        c2 = user2listCopyTo1[0] ^ (user2input[0] & 0b1)
    elif a2 == 0 and y2 == 1:
        c2 = user2listCopyTo1[1] ^ (user2input[1] & 0b1)
    elif a2 == 1 and y2 == 0:
        c2 = user2listCopyTo1[2] ^ (user2input[2] & 0b1)
    elif a2 == 1 and y2 == 1:
        c2 = user2listCopyTo1[3] ^ (user2input[3] & 0b1)

    log_message(index2, f"User {index2 + 1} calculated c2: {c2}")

    return c1, c2

# Function to calculate secure XOR
def secure_xor(user_index, a1, b1):
    # Calculate the XOR
    c1 = a1 ^ b1

    # Log the operation
    log_message(user_index, f"User {user_index + 1} calculated secure XOR: {a1} XOR {b1} = {c1}")

    return c1

# Function to calculate secure NOT
def secure_not(user_index, a1):
    # Calculate the NOT operation (bitwise NOT)
    c = ~a1 & 0b1  # Ensure the result is a single bit (0 or 1)

    # Log the operation
    log_message(user_index, f"User {user_index + 1} calculated secure NOT: NOT {a1} = {c}")

    return c

def secure_and(index1, index2, index3, a1, b1, a2, b2, a3, b3):
    # Perform oblivious transfers
    c12, c21 = oblivious_transfer(a1, b1, a2, b2, index1, index2)
    c13, c31 = oblivious_transfer(a1, b1, a3, b3, index1, index3)
    c23, c32 = oblivious_transfer(a2, b2, a3, b3, index2, index3)

    # Calculate c1, c2, c3
    c1 = c12 ^ c13 ^ (a1 & b1)
    c2 = c21 ^ c23 ^ (a2 & b2)
    c3 = c31 ^ c32 ^ (a3 & b3)

    # Log the results for each user
    log_message(index1, f"User {index1 + 1} received c1 = {c12} ^ {c13} ^ {a1} & {b1} = {c1}")
    log_message(index2, f"User {index2 + 1} received c2 = {c21} ^ {c23} ^ {a2} & {b2} = {c2}")
    log_message(index3, f"User {index3 + 1} received c3 = {c31} ^ {c32} ^ {a3} & {b3} = {c3}")

    return c1, c2, c3

# Secure Half Adder function
def secure_half_adder(a1, b1, a2, b2, a3, b3):
    # Calculate the sum for each user
    sumUser1 = secure_xor(0, a1, b1)
    sumUser2 = secure_xor(1, a2, b2)
    sumUser3 = secure_xor(2, a3, b3)

    # Calculate the carry for each user using secure_and
    carryUser1, carryUser2, carryUser3 = secure_and(0, 1, 2, a1, b1, a2, b2, a3, b3)

    # Log the sum and carry calculations for each user
    log_message(0, f"User 1: sum = {sumUser1}, carry = {carryUser1}")
    log_message(1, f"User 2: sum = {sumUser2}, carry = {carryUser2}")
    log_message(2, f"User 3: sum = {sumUser3}, carry = {carryUser3}")

    return sumUser1, sumUser2, sumUser3, carryUser1, carryUser2, carryUser3

def secure_full_adder(a1, b1, c1, a2, b2, c2, a3, b3, c3, cond):
    # Calculate the sum for each user
    user1xor = secure_xor(0, a1, b1)
    user1sum = secure_xor(0, user1xor, c1)
    user2xor = secure_xor(1, a2, b2)
    user2sum = secure_xor(1, user2xor, c2)
    user3xor = secure_xor(2, a3, b3)
    user3sum = secure_xor(2, user3xor, c3)

    # Log the sum for each user
    log_message(0, f"User 1: SUM = {user1sum}")
    log_message(1, f"User 2: SUM = {user2sum}")
    log_message(2, f"User 3: SUM = {user3sum}")

    # Initialize carry variables
    user1carry = user2carry = user3carry = None

    # Calculate the carry if cond != -1
    if cond != -1:
        carry1user1, carry1user2, carry1user3 = secure_and(0, 1, 2, a1, b1, a2, b2, a3, b3)
        carry2user1, carry2user2, carry2user3 = secure_and(0, 1, 2, user1xor, c1, user2xor, c2, user3xor, c3)

        carry1user1 = secure_not(0, carry1user1)
        carry2user1 = secure_not(0, carry2user1)

        user1carry, user2carry, user3carry = secure_and(0, 1, 2, carry1user1, carry2user1, carry1user2, carry2user2, carry1user3, carry2user3)

        user1carry = secure_not(0, user1carry)

        # Log the carry for each user
        log_message(0, f"User 1: CARRY = {user1carry}")
        log_message(1, f"User 2: CARRY = {user2carry}")
        log_message(2, f"User 3: CARRY = {user3carry}")

    return user1sum, user2sum, user3sum, user1carry, user2carry, user3carry

def secure_4bit_addition(list1, list2):
    # Initialize the result lists for each user
    result_user1 = []
    result_user2 = []
    result_user3 = []

    # Initialize carry bits for each user
    carry1 = carry2 = carry3 = 0

    # Loop over the bits
    for i in range(4):
        a1, a2, a3 = list1[i]
        b1, b2, b3 = list2[i]

        if i == 0:
            # Use half adder for the LSB
            sum1, sum2, sum3, carry1, carry2, carry3 = secure_half_adder(a1, b1, a2, b2, a3, b3)
        elif i == 3:
            # Use full adder without carry calculation for the MSB
            sum1, sum2, sum3, _, _, _ = secure_full_adder(a1, b1, carry1, a2, b2, carry2, a3, b3, carry3, -1)
        else:
            # Use full adder for other bits
            sum1, sum2, sum3, carry1, carry2, carry3 = secure_full_adder(a1, b1, carry1, a2, b2, carry2, a3, b3, carry3, 0)

        # Append the sum to the result lists
        result_user1.append(sum1)
        result_user2.append(sum2)
        result_user3.append(sum3)

    return result_user1, result_user2, result_user3

# Function to convert a list of bits to an integer
def bits_to_int(bits, reverse=False):
    bin_str = ''.join(str(bit) for bit in bits)
    if reverse:
        bin_str = bin_str[::-1]
    return int(bin_str, 2)

# Function to convert an integer to a binary string with leading zeros
def int_to_bin_str(value, length=4):
    return f"{value:0{length}b}"

# Function to perform XOR on a list of binary strings
def xor_binary_strings(bin_list, reverse=False):
    result = bits_to_int([int(bit) for bit in bin_list[0]], reverse)
    for bin_str in bin_list[1:]:
        result ^= bits_to_int([int(bit) for bit in bin_str], reverse)
    return int_to_bin_str(result, len(bin_list[0]))

# Function to send and receive results
def send_receive_results(result_user1, result_user2, result_user3):
    # Convert each list to an integer with reverse=True to treat first bit as LSB
    int_result_user1 = bits_to_int(result_user1, reverse=True)
    int_result_user2 = bits_to_int(result_user2, reverse=True)
    int_result_user3 = bits_to_int(result_user3, reverse=True)

    # Send results
    encrypted_message_12, encrypted_part_12 = send_message_logic(0, 1, int_result_user1)
    encrypted_message_13, encrypted_part_13 = send_message_logic(0, 2, int_result_user1)
    encrypted_message_21, encrypted_part_21 = send_message_logic(1, 0, int_result_user2)
    encrypted_message_23, encrypted_part_23 = send_message_logic(1, 2, int_result_user2)
    encrypted_message_31, encrypted_part_31 = send_message_logic(2, 0, int_result_user3)
    encrypted_message_32, encrypted_part_32 = send_message_logic(2, 1, int_result_user3)

    # Receive and decode results
    received_user1_from_2 = receive_message_logic(0, encrypted_message_21)
    received_user1_from_3 = receive_message_logic(0, encrypted_message_31)
    received_user2_from_1 = receive_message_logic(1, encrypted_message_12)
    received_user2_from_3 = receive_message_logic(1, encrypted_message_32)
    received_user3_from_1 = receive_message_logic(2, encrypted_message_13)
    received_user3_from_2 = receive_message_logic(2, encrypted_message_23)

    # Convert received integers back to binary strings with reverse=True to get original order
    user1_results = [int_to_bin_str(int_result_user1)[::-1], int_to_bin_str(received_user1_from_2)[::-1], int_to_bin_str(received_user1_from_3)[::-1]]
    user2_results = [int_to_bin_str(int_result_user2)[::-1], int_to_bin_str(received_user2_from_1)[::-1], int_to_bin_str(received_user2_from_3)[::-1]]
    user3_results = [int_to_bin_str(int_result_user3)[::-1], int_to_bin_str(received_user3_from_1)[::-1], int_to_bin_str(received_user3_from_2)[::-1]]

    # Log received messages
    log_message(0, f"User 1 received: {user1_results}")
    log_message(1, f"User 2 received: {user2_results}")
    log_message(2, f"User 3 received: {user3_results}")

    # Perform XOR on the binary strings for each user with reverse=True to treat first bit as LSB
    final_user1_result = xor_binary_strings(user1_results, reverse=True)
    final_user2_result = xor_binary_strings(user2_results, reverse=True)
    final_user3_result = xor_binary_strings(user3_results, reverse=True)

    # Log final XOR results
    log_message(0, f"User 1 calculated XOR: {final_user1_result} = {int(final_user1_result, 2)}")
    log_message(1, f"User 2 calculated XOR: {final_user2_result} = {int(final_user2_result, 2)}")
    log_message(2, f"User 3 calculated XOR: {final_user3_result} = {int(final_user3_result, 2)}")

# Function to perform secure 4-bit addition twice and log messages
def perform_secure_addition():
    # First calculation using index 0 and index 1 of user_split_bits
    list1_first = [
        [user_split_bits[0][i][0], user_split_bits[1][i][0], user_split_bits[2][i][0]]
        for i in range(4)
    ]
    list2_first = [
        [user_split_bits[0][i][1], user_split_bits[1][i][1], user_split_bits[2][i][1]]
        for i in range(4)
    ]

    # Perform the first secure 4-bit addition
    result_user1, result_user2, result_user3 = secure_4bit_addition(list1_first, list2_first)

    # Log the results of the first addition
    log_message(0, f"User 1: Secure addition result of User 1 and User 2 values: {result_user1}")
    log_message(1, f"User 2: Secure addition result of User 2 and User 1 values: {result_user2}")
    log_message(2, f"User 3: Secure addition result of User 3 and User 1 values: {result_user3}")

    # Second calculation using index 3 of user_split_bits and results from the first calculation
    list1_second = [
        [user_split_bits[0][i][2], user_split_bits[1][i][2], user_split_bits[2][i][2]]
        for i in range(4)
    ]
    list2_second = [
        [result_user1[i], result_user2[i], result_user3[i]]
        for i in range(4)
    ]

    # Perform the second secure 4-bit addition
    final_user1_result, final_user2_result, final_user3_result = secure_4bit_addition(list1_second, list2_second)

    # Log the results of the second addition
    log_message(0, f"User 1: Final secure addition result: {final_user1_result}")
    log_message(1, f"User 2: Final secure addition result: {final_user2_result}")
    log_message(2, f"User 3: Final secure addition result: {final_user3_result}")

    return final_user1_result, final_user2_result, final_user3_result

# Function to simulate the protocol steps
def start_simulation():
    global user3_initial_value, user3_accumulated_value, simulation_active, user_initial_bits

    if None in user_inputs:
        messagebox.showerror("Incomplete Input", "Please enter values for all users.")
        return

    user3_initial_value = user_inputs[2]
    user3_accumulated_value = user3_initial_value  # Initialize the accumulated value with the initial value

    # Secure bit splitting and logging
    for i in range(3):
        bits = [int(b) for b in format(user_inputs[i], '04b')]
        user_initial_bits[i] = split_and_log_bits(i, bits)
        user_split_bits[i] = user_initial_bits[i]

    # Log initial state of the bits for each user
    for i in range(3):
        log_message(i, f"Initial state of bits for User {i + 1}: {user_split_bits[i]}")

    prepare_bits_to_send()

    # Securely send bits
    for i in range(3):
        send_bits(i)

    # Securely receive bits
    for i in range(3):
        receive_bits(i)

    simulation_active = True

    # Log the final state of the bits for each user
    for i in range(3):
        log_message(i, "\nFinal state of bits:")
        for j in range(4):
            log_message(i, f"Bit {j}: {user_split_bits[i][j]}")

    final_user1_result, final_user2_result, final_user3_result = perform_secure_addition()
    send_receive_results(final_user1_result, final_user2_result, final_user3_result)

    # Update button states
    start_button.config(state=tk.DISABLED)
    reset_button.pack(pady=20, fill="x", expand=True)
    root.update_idletasks()  # Ensure the window layout is updated

# Buttons for user input
for i in range(3):
    button = tk.Button(input_frame, text=f"Enter for User {i + 1}",
                       command=lambda idx=i: enter_value(idx),
                       font=button_font, activebackground=button_active_color, bg=button_background, relief="flat")
    button.pack(pady=5, fill="x", expand=True)

# Button to start the simulation
start_button = tk.Button(input_frame, text="Start Simulation", command=start_simulation,
                         font=button_font, activebackground=button_active_color, bg="#F76C6C", relief="flat")
start_button.pack(pady=20, fill="x", expand=True)

# Set a minimum window size
root.update()
root.minsize(root.winfo_width(), root.winfo_height())

# Center the main window on the screen
root.eval('tk::PlaceWindow . center')

# Run the main event loop
root.mainloop()
