#!/usr/bin/env python3
"""
A python script for encripting passwords
"""
import bcrypt


def hash_password(password: str) -> bytes:
    """
        Function to hash password using random salt.
    """
    return bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())


def is_valid(hashed_password: bytes, password: str) -> bool:
    '''
        Function to check validity of a password
    '''
    return bcrypt.checkpw(password.encode('utf-8'), hashed_password)
