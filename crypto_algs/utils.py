def sieve_of_eratosthenes(limit):
    """
    Generates prime numbers up to a specified limit using the Sieve of Eratosthenes.

    Args:
        limit (int): The upper bound (inclusive) for prime number generation.

    Returns:
        list: A list containing all prime numbers up to the limit.
    """
    primes = [True] * (limit + 1)  # Initialize a boolean array, marking all numbers as potentially prime
    primes[0] = primes[1] = False  # 0 and 1 are not prime

    for num in range(2, int(limit**0.5) + 1):
        if primes[num]:  # If num is prime, mark its multiples as not prime
            for multiple in range(num * num, limit + 1, num):
                primes[multiple] = False

    # Collect all numbers that are still marked as True
    prime_numbers = [i for i, is_prime in enumerate(primes) if is_prime]
    return prime_numbers