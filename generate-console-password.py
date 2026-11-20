"""Generate the web console password hash without echoing the password."""
import getpass
import hashlib
import secrets


def main():
    password = getpass.getpass('New web console password: ')
    if not password:
        raise SystemExit('The password must not be empty.')
    if password != getpass.getpass('Confirm password: '):
        raise SystemExit('Passwords do not match.')
    salt = secrets.token_bytes(16)
    derived = hashlib.pbkdf2_hmac('sha256', password.encode(), salt, 600000)
    print(salt.hex() + ':' + derived.hex())


if __name__ == '__main__':
    main()
