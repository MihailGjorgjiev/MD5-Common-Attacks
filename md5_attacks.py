import itertools
import os
import json
import struct
import string
import random

from simplemd5 import SimpleMD5
from symbol_iterator import SymbolSequenceIterator


class MD5_Attacks:

    def md5_hash(self, data):
        return SimpleMD5().hash(data.encode()).hex()

    def save_json(self, dictionary, path):
        if os.path.exists(path):
            os.chmod(path, 0o666)
        with open(path, "w") as doc:
            json.dump(dictionary, doc)

    def random_string(self, length=8):
        letters = string.ascii_lowercase
        return ''.join(random.choice(letters) for _ in range(length))

    def find_collision(self):
        hashes = dict()

        for i in itertools.count():
            message = str(i)
            hash_val = self.md5_hash(message)
            if hash_val in hashes:
                print(
                    f"Collision found: {message} and {hashes[hash_val]} have the same hash value : {hash_val}")
                return message, hashes[hash_val]

            hashes[hash_val] = message
            # if i % 1_000_000 == 0:
            #     self.save_json(hashes,"collision/dictionary.json")

    def chosen_prefix_collision(self, prefix1, prefix2, suffix_length=8):

        while True:
            suffix1 = self.random_string(suffix_length)
            suffix2 = self.random_string(suffix_length)
            hash1 = self.md5_hash(prefix1 + suffix1)
            hash2 = self.md5_hash(prefix2 + suffix2)
            if hash1 == hash2:
                print(
                    f"Collision found: {prefix1 + suffix1} and {prefix2 + suffix2} have the same hash value : {hash1}")
                return (prefix1 + suffix1, prefix2 + suffix2, hash1)

    def birthday_attack(self, hash_function, length=6, max_attempts=2 ** 16):
        hashes = {}
        for _ in range(max_attempts):
            s = self.random_string(length)
            hash_value = hash_function(s)
            if hash_value in hashes and hashes[hash_value] != s:
                print(f"Collision found: '{hashes[hash_value]}' and '{s}' both hash to {hash_value.hex()}")
                return hashes[hash_value], s
            hashes[hash_value] = s
        print("No collision found")
        return None

    def preimage_attack(self, target_hash):
        iterator = SymbolSequenceIterator(max_length=16)
        for message in iterator:
            if SimpleMD5().hash(message).hex() == target_hash:
                print(f"Collision found: '{message}' has hash {target_hash}")
                return message, target_hash

        return None

    def second_preimage_attack(self, original_message):
        original_hash = SimpleMD5().hash(original_message).hex()
        iterator = SymbolSequenceIterator(max_length=16)
        for message in iterator:
            if SimpleMD5().hash(message).hex() == original_hash and message != original_message:
                print(f"Collision found: '{message}' has hash {original_hash}")
                return message, original_hash

        return None

    def length_extension_attack(self, original_message, original_hash, append_message):
        original_length = len(original_message)
        original_padding = SimpleMD5()._md5_padding(original_length)

        md5_fn = SimpleMD5()

        md5_fn.state = list(struct.unpack('<I', original_hash))

        md5_fn.update(append_message)

        new_hash = md5_fn.finalize()

        new_message = original_message + original_padding + append_message

        return new_message, new_hash
