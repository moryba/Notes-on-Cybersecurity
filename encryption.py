import string
from time import sleep

alphabet = string.ascii_lowercase

def encrypt():

    print("Caesar Cipher Demd. \n")
    message = input("Message to encrypt: ").lower()
    print()
    key = int(input("Enter your key: "))

    encrypted_message = " "

    for c in message:
        if c in alphabet:
            position = alphabet.find(c)
            new_position = (position + key) % 26
            new_character = alphabet[new_position]
            encrypted_message += new_character
        else:
            encrypted_message += c

    print("\nEncrypting..\n")
    print("Your encrypted message is :\n")
    print(encrypted_message)

#Encrypt a message by typing a message and then choosing an integer for you encryption
encrypt()

