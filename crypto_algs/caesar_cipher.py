def shift_characters(text, shift_amount):
    shifted_chars = []
    for char in text:
        # Handle only alphabetic characters, wrapping around the alphabet
        if 'a' <= char <= 'z':
            shifted_char_code = ord('a') + (ord(char) - ord('a') + shift_amount) % 26
            shifted_chars.append(chr(shifted_char_code))
        elif 'A' <= char <= 'Z':
            shifted_char_code = ord('A') + (ord(char) - ord('A') + shift_amount) % 26
            shifted_chars.append(chr(shifted_char_code))
        else:
            # Keep non-alphabetic characters as they are
            shifted_chars.append(char)
    return "".join(shifted_chars)

if __name__ == "__main__":
    # Example usage:
    original_string = "hello World!"
    shifted_string = shift_characters(original_string, 1)
    print(f"Original: {original_string}")
    print(f"Shifted (character-wise): {shifted_string}")