def sieve(n):
    is_prime = bytearray(b"\x01") * (n + 1)
    is_prime[0] = is_prime[1] = 0
    for i in range(2, int(n**0.5) + 1):
        if is_prime[i]:
            is_prime[i*i::i] = bytearray(len(is_prime[i*i::i]))
    return sum(is_prime)

print(sieve(500000))
