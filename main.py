from simplemd5 import SimpleMD5
import md5_attacks

if __name__ == '__main__':
    original_message = "test"
    original_hash = SimpleMD5().hash(original_message)
    append_message = "1234"

    prefix1 = "This is a prefix."
    prefix2 = "This is also a prefix."

    md5_attacks.MD5_Attacks().find_collision()
    md5_attacks.MD5_Attacks().birthday_attack(SimpleMD5().hash, 16, 2 ** 32)

    md5_attacks.MD5_Attacks().preimage_attack(original_hash.hex())  # use smaller message for example

    print("Original message:", original_message)
    print("Original hash:", original_hash.hex())
    new_message, new_hash = md5_attacks.MD5_Attacks().length_extension_attack(original_message.encode(), original_hash,
                                                                              append_message.encode())
    print("New message:", new_message)
    print("New hash:", new_hash.hex())

    md5_attacks.MD5_Attacks().chosen_prefix_collision(prefix1, prefix2)  # takes too long

    md5_attacks.MD5_Attacks().second_preimage_attack(original_message)  # takes too long
