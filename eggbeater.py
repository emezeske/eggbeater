import pycuda.compiler as compiler
import pycuda.driver as driver
import pycuda.autoinit
import numpy as np
import time
import struct
import sha
import socket
import binascii
import random

# This is the Meebo secret that eggbeater is searching for.  If you
# want to see eggbeater complete in an interactive amount of time,
# change this to something with 6 or 7 characters from the set [a-z0-9].
MEEBO_SECRET = 'g00se3gg5'
MAX_SECRET_LEN = len(MEEBO_SECRET)
KEYSPACE_SIZE = 36 ** MAX_SECRET_LEN

# The block and grid counts control the layout of the GPU kernel
# threads that run the SHA-1 calculations.  They seem to be highly
# GPU-specific; you may have to lower them to get things working
# on your GPU.
BLOCK_COUNT = 128
GRID_COUNT = 16384
THREAD_COUNT = BLOCK_COUNT * GRID_COUNT

# This has to be equal to sizeof(sha1_partial_state) from eggbeater.cu.
SIZEOF_SHA1_PARTIAL_STATE = 16 * 4

def make_session_key(endpoint):
    ip, port = endpoint
    assert port >= 0 and port <= 65535
    ip_int = struct.unpack('I', socket.inet_aton(ip))[0]
    port_int = socket.htons(int(port))
    salt_hex = binascii.hexlify(struct.pack('f', random.random()))
    key_hex = '%0.32X%0.4X%s' % (ip_int, port_int, salt_hex)
    sha1 = sha.new(key_hex + MEEBO_SECRET)
    # The actual Meebo implementation does not provide the last six bytes,
    # so we chop them off and replace them with zeros so that the cracker
    # can't cheat.
    digest_bytes = sha1.digest()[0:14] + '\x00' * 6
    digest = struct.unpack('>5I', digest_bytes)
    return np.fromstring(key_hex, dtype=np.uint8), np.array(digest, dtype=np.uint32)

def get_cuda_functions():
    source = open('./eggbeater.cu')
    try:
        module = compiler.SourceModule(source.read())
    finally:
        source.close()
    return module.get_function('precalculate'), module.get_function('crack')

def run():
    precalculate, crack = get_cuda_functions()
    session_key, digest = make_session_key(('1.2.3.4', 80))
    print 'Original digest: %08x%08x%08x%08x%08x' % tuple(digest)
    key_found = np.array([0], dtype=np.uint32)

    precalculated_state = np.array([0] * SIZEOF_SHA1_PARTIAL_STATE, dtype=np.uint8)
    precalculate(
        driver.In(session_key),
        driver.Out(precalculated_state),
        block=(1, 1, 1))

    start_time = time.time()
    tick_time = start_time
    secret_number = 0

    while secret_number < KEYSPACE_SIZE:
        crack(
            driver.In(precalculated_state),
            driver.In(digest),
            driver.In(np.array([secret_number], dtype=np.uint64)),
            driver.InOut(key_found),
            block=(BLOCK_COUNT, 1, 1),
            grid=(GRID_COUNT, 1))
        if key_found[0] != 0:
            break
        now = time.time()
        if now > tick_time + 1.0:
            tick_time = now
            seconds = int(now - start_time)
            if seconds == 0:
                seconds = 1
            print 'Processed %s secrets in %s seconds (%s/s) (%0.2f%%)' % \
                (secret_number, seconds,
                 secret_number / seconds,
                 100.0 * secret_number / KEYSPACE_SIZE)
        secret_number += THREAD_COUNT;
        secret_number = min(secret_number, KEYSPACE_SIZE)

if __name__ == '__main__':
    run()
