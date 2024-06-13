import itertools
import string


class SymbolSequenceIterator:
    def __init__(self, max_length):
        self.symbols = string.ascii_letters + string.digits + string.punctuation
        self.max_length = max_length
        self.current_length = 1
        self.current_iterator = itertools.product(self.symbols, repeat=self.current_length)

    def __iter__(self):
        return self

    def __next__(self):
        try:
            return ''.join(next(self.current_iterator))
        except StopIteration:
            self.current_length += 1
            if self.current_length > self.max_length:
                raise StopIteration
            self.current_iterator = itertools.product(self.symbols, repeat=self.current_length)
            return ''.join(next(self.current_iterator))

# Usage example
