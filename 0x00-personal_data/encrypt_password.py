#!/usr/bin/env python3
"""A module for encrypt passwd.
"""
import bcrypt


def hash_password(password: str) -> bytes:
    """Hashes a passwd using a random salt.
    """
    return bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())


def is_valid(hashed_password: bytes, password: str) -> bool:
    """Checks is a hashed passwd was formed from the given passwd.
    """
    return bcrypt.checkpw(password.encode('utf-8'), hashed_password)
