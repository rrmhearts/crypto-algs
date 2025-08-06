def rotate_string_left(s, n=1):
    """Rotates a string to the left by n characters."""
    n %= len(s)  # Handle shifts larger than string length
    return s[n:] + s[:n]

def rotate_string_right(s, n=1):
    """Rotates a string to the right by n characters."""
    n %= len(s)
    return s[-n:] + s[:-n]

def mirror_swap_bytearray(data: bytearray) -> bytearray:
    """
    Cuts a bytearray in half, swaps bytes across a mirror to other half
     before it swaps the two halves.

    Args:
        data: The bytearray to split and swap.

    Returns:
        A new bytearray with the mirrored halves swapped.
        If the bytearray has an odd length, the middle byte
        will be part of the first half after the split.
    """
    length = len(data)
    midpoint = length // 2  # Integer division for the midpoint

    # Slice the bytearray into two halves
    first_half = data[:midpoint]
    second_half = data[midpoint:]

    # Assuming first_half and second_half are bytes objects
    first_half_mutable = bytearray(first_half)
    second_half_mutable = bytearray(second_half)

    length_each = len(first_half)
    # Mirror swap
    for i in range(length_each):
        # Perform the swap using the mutable bytearray objects
        first_half_mutable[i], second_half_mutable[length_each-i-1] = second_half_mutable[length_each-i-1], first_half_mutable[i]

    first_half = bytes(first_half_mutable)
    second_half = bytes(second_half_mutable)
    swapped_data = second_half + first_half
    return swapped_data

def split_and_swap_bytearray(data: bytearray) -> bytearray:
    """
    Cuts a bytearray in half and swaps the two halves.

    Args:
        data: The bytearray to split and swap.

    Returns:
        A new bytearray with the halves swapped.
        If the bytearray has an odd length, the middle byte
        will be part of the first half after the split.
    """
    length = len(data)
    midpoint = length // 2  # Integer division for the midpoint

    # Slice the bytearray into two halves
    first_half = data[:midpoint]
    second_half = data[midpoint:]

    # Concatenate the halves in swapped order
    swapped_data = second_half + first_half
    return swapped_data

# Example usage:
if __name__ == "__main__":
    original_string = "python"
    left_shifted_string = rotate_string_left(original_string, 1)
    right_shifted_string = rotate_string_right(original_string, 1)
    print(f"Original: {original_string}")
    print(f"Shifted (left rotation): {left_shifted_string}")
    print(f"Shifted (right rotation): {right_shifted_string}")


    # Example usage:
    original_bytearray = bytearray(b'abcdefgh')
    swapped_result = split_and_swap_bytearray(original_bytearray)
    print(f"Original: {original_bytearray}")
    print(f"Swapped: {swapped_result}")

    original_bytearray_odd = bytearray(b'abcde')
    swapped_result_odd = split_and_swap_bytearray(original_bytearray_odd)
    print(f"Original (odd length): {original_bytearray_odd}")
    print(f"Swapped (odd length): {swapped_result_odd}")
