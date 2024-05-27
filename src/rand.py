import random

def gen_random_name(strlen):
    rstr = ''
    for i in range(strlen):
        rstr += (str(chr(random.randint(97, 122))))
    return rstr