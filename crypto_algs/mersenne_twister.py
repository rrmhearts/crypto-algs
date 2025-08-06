import random

class MersenneTwister:
    def __init__(self):
        # One initialization
        self.state = [ random.randbytes(4) for _ in range(624)]
        # index of next word
        self.next_word = 0

    def refresh(self, n):
        # Just update the n bytes of memory
        for _ in range(n):
            cword, nword = self.next_word, (self.next_word+1) % len(self.state)
            state397 = self.state[(cword+397) % len(self.state)]
            A_input = (int.from_bytes(self.state[cword], byteorder='big') & 0x80000000) \
                | (int.from_bytes(self.state[nword], byteorder='big') & 0xffffffff)
            A_func = (A_input >> 1) if (A_input&0x80000000) == 0x00000000 \
                else (A_input >> 1) ^ 0x9908b0df
            ans = int.from_bytes(state397, byteorder='big') ^ A_func
            self.state[cword] = ans.to_bytes(4, byteorder='big')
            # Now that the previous word is updated, update the current state
            self.next_word = nword
    def next(self, n):
        ret = b''.join(self.state[b] for b in range(self.next_word, self.next_word+n))
        self.refresh(n)
        return ret

if __name__ == "__main__":
    # Testing
    mt = MersenneTwister()
    print(mt.next(5))
    print(mt.next(1))

    collector = []
    for i in range(9000):
        nextv = mt.next(1)
        assert nextv not in collector, f"There should be no repeats: {nextv}"
        collector.append(nextv)
