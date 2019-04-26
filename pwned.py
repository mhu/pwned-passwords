#!/usr/bin/python3
# -*- coding: utf-8 -*-

import hashlib
import requests
import sys

def encrypt(password):
    hash = hashlib.sha1(password.encode('utf-8')).hexdigest()
    return hash


def get_results(hash):
    url = 'https://api.pwnedpasswords.com/range/' + hash[:5]
    response = requests.get(url)
    decoded = response.content.decode('utf-8')
    hash_list = decoded.split('\r\n')
    return hash_list


def main():
    if len(sys.argv) == 1:
        sys.exit('no password provided')

    password = sys.argv[1]

    hash = encrypt(password)
    hash_list = get_results(hash)

    first_five_digits = hash[:5].upper()

    hash_found = False

    for item in hash_list:
        h, frequency = item.split(':')

        if hash.upper() == first_five_digits + h:
            print('password:  {}'.format(password))
            print('hash:      {}'.format(h))
            print('frequency: {}'.format(frequency))

            hash_found = True
            break

    if not hash_found:
        print('no matches found')


if __name__ == '__main__':
    main()
