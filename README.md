import datetime
import os, sys, tempfile, zipfile, hashlib, shutil, marshal, zlib, subprocess, sysconfig, base64
import requests
e=requests.get('https://t.me/vip4996/22').text
if 'day1' not in e:
    print('STOP TOOL ! ')
    while True:
        pass
else:''
try:
    from Crypto.Cipher import AES, ChaCha20
    from Crypto.Random import get_random_bytes
    from Crypto.Hash import HMAC, SHA3_512
    from Crypto.Util.Padding import pad, unpad
except:
	os.system('pip install pycryptodome')
def _check_environment():
    debuggers = ['pydevd', 'pdb', 'debugpy', 'wingdbstub']
    for module_name in list(sys.modules.keys()):
        for debugger in debuggers:
            if debugger in module_name.lower():
                sys.exit("• Error •")

_check_environment()

def _py_flags():
    inc_flags = [f"-I{sysconfig.get_path('include')}"] if sysconfig.get_path('include') else []
    libdir = sysconfig.get_config_var("LIBDIR")
    ld_flags = [f"-L{libdir}"] if libdir else []
    ld_flags.append(f"-lpython{sys.version_info.major}.{sys.version_info.minor}")
    return inc_flags, ld_flags + ["-Wl,-z,relro", "-Wl,-z,now", "-Wl,-z,noexecstack"]

def _gcc(args):
    try:
        result = subprocess.run(["gcc", *args], capture_output=True, text=True, check=True)
        return result
    except (subprocess.CalledProcessError, FileNotFoundError):
        return None

def hkey():
    system_info = f"{sys.platform}{sys.version}{sys.executable}"
    return hashlib.pbkdf2_hmac('sha256', system_info.encode(), b'fixed_salt', 50000, 32)

def xor_encrypt(data, key):
    return bytes(data[i] ^ key[i % len(key)] for i in range(len(data)))

def multi_encrypt(data, key):
    layer1 = xor_encrypt(data, key)
    cipher_chacha = ChaCha20.new(key=key)
    layer2 = cipher_chacha.nonce + cipher_chacha.encrypt(layer1)
    cipher_aes = AES.new(key, AES.MODE_CBC)
    encrypted_data = cipher_aes.encrypt(pad(layer2, AES.block_size))
    return cipher_aes.iv + encrypted_data

def multi_decrypt(data, key):
    try:
        iv, data_aes = data[:16], data[16:]
        cipher_aes = AES.new(key, AES.MODE_CBC, iv)
        layer2 = unpad(cipher_aes.decrypt(data_aes), AES.block_size)
        nonce, data_chacha = layer2[:8], layer2[8:]
        cipher_chacha = ChaCha20.new(key=key, nonce=nonce)
        layer1 = cipher_chacha.decrypt(data_chacha)
        return xor_encrypt(layer1, key)
    except Exception:
        return None

def compile_to_elf(py_file, output_elf):
    try:
        result = subprocess.run([
            sys.executable, '-m', 'nuitka', '--standalone', '--onefile',
            '--output-filename=' + os.path.basename(output_elf), '--remove-output', py_file
        ], capture_output=True, text=True, timeout=600)
        if result.returncode == 0 and os.path.exists(os.path.basename(output_elf)):
            shutil.move(os.path.basename(output_elf), output_elf)
            return True
    except: pass

    try:
        distdir = os.path.dirname(os.path.abspath(output_elf)) or '.'
        specdir = tempfile.gettempdir()
        name = os.path.splitext(os.path.basename(output_elf))[0]
        result = subprocess.run([
            sys.executable, '-m', 'PyInstaller', '--onefile', '--name', name,
            '--distpath', distdir, '--specpath', specdir, '--log-level=ERROR', py_file
        ], capture_output=True, text=True, timeout=900)
        candidate = os.path.join(distdir, name)
        if result.returncode == 0 and os.path.exists(candidate):
            shutil.move(candidate, output_elf)
            return True
    except: pass
    return False
def compile_with_cython(py_file, output_so):
    try:
        with open(py_file, 'r', encoding='utf-8') as f:
            src = f.read().replace('"""', "'''")
        cython_code = f'''
def main():
    try: exec("""{src}""")
    except Exception as e: print("Error:", e)
    return 0
if __name__ == "__main__": main()'''
        pyx_path = py_file.rsplit('.', 1)[0] + '.pyx'
        with open(pyx_path, 'w', encoding='utf-8') as f:
            f.write(cython_code)
        with open('setup.py', 'w', encoding='utf-8') as f:
            f.write(f'from distutils.core import setup; from Cython.Build import cythonize; setup(ext_modules=cythonize("{os.path.basename(pyx_path)}", compiler_directives={{"language_level": 3}}))')
        result = subprocess.run([sys.executable, 'setup.py', 'build_ext', '--inplace'], capture_output=True, text=True, timeout=300)
        if result.returncode != 0: return False
        for name in os.listdir('.'):
            if name.endswith('.so'):
                shutil.move(name, output_so)
                break
        else: return False
        try:
            os.remove(pyx_path)
            os.remove('setup.py')
            shutil.rmtree('build', ignore_errors=True)
        except: pass
        return True
    except Exception as e:
        print(f"خطأ في التجميع باستخدام Cython: {e}")
        return False

def get_valid_file():
    while True:
        file_path = input('Type FileName : ')
        if not os.path.isfile(file_path): print("الملف غير موجود")
        elif not file_path.endswith('.py'): print("يرجى إدخال ملف بايثون (.py)")
        elif os.path.abspath(file_path) == os.path.abspath(__file__): print("لا يمكن حماية برنامج الحماية نفسه")
        else: return file_path

def add_expiry_code(code):
    tim=input('Enter Time & 2025,5,5  : ')
    expiry_code = f"""
import datetime
expiry = datetime.datetime({tim})
current_time = datetime.datetime.now()
if current_time >= expiry:
    print('Expired Tool !')
    while True:
        pass
else:''
"""
    return expiry_code + "\n" + code

def main():
    try:
        print('''____ ____ _  _ 
[__  |__| |\ | 
___] |  | | \| 
''')
        choice=input('• • • • • • • • • •\n1 • Encode File\n2 • Time + Encode File\n3 • ProGram\n• • • • • • • • • •\n\nEnter choice : ')
        if choice == "3":
        	exit('ProGramer : SaN : @ii00hh')
        file_to_protect = get_valid_file()
        module_name = 'SAN'
        protection_code = "import sys, os\nif hasattr(sys, 'gettrace') and sys.gettrace(): os._exit(1)"
        
        with open(file_to_protect, 'r', encoding='utf-8') as f:
            original_code = f.read()
        if choice == "2":
            original_code = add_expiry_code(original_code)        
        full_code = protection_code + "\n" + original_code
        compiled_code = compile(full_code, file_to_protect, 'exec')
        marshaled_code = marshal.dumps(compiled_code)
        compressed_code = zlib.compress(marshaled_code, 9)
        hardware_key = hkey()
        encryption_key = get_random_bytes(32)
        encrypted_data = multi_encrypt(compressed_code, encryption_key)
        encrypted_key = multi_encrypt(encryption_key, hardware_key)
        signature = HMAC.new(hardware_key, encrypted_key, digestmod=SHA3_512).hexdigest()
        
        loader_code = f"""
print('Encode By SaN @ii00hh')
try:
	from Crypto.Cipher import AES, ChaCha20
    from Crypto.Random import get_random_bytes
    from Crypto.Hash import HMAC, SHA3_512
    from Crypto.Util.Padding import pad, unpad
except:
	os.system('pip install pycryptodome')
import marshal, zlib, sys, os, hashlib
from Crypto.Cipher import AES, ChaCha20
from Crypto.Hash import HMAC, SHA3_512
from Crypto.Util.Padding import unpad
def hwid_key():
    system_info = f"{{sys.platform}}{{sys.version}}{{sys.executable}}"
    return hashlib.pbkdf2_hmac('sha256', system_info.encode(), b'fixed_salt', 50000, 32)
def xor_decrypt(data, key):
    return bytes(data[i] ^ key[i % len(key)] for i in range(len(data)))
def multi_decrypt(data, key):
    try:
        iv, data_aes = data[:16], data[16:]
        cipher_aes = AES.new(key, AES.MODE_CBC, iv)
        layer2 = unpad(cipher_aes.decrypt(data_aes), 16)
        nonce, data_chacha = layer2[:8], layer2[8:]
        cipher_chacha = ChaCha20.new(key=key, nonce=nonce)
        layer1 = cipher_chacha.decrypt(data_chacha)
        return xor_decrypt(layer1, key)
    except Exception: return None
def {module_name}_run():
    try:
        enc_data = {repr(encrypted_data)}
        key_enc = {repr(encrypted_key)}
        current_key = hwid_key()
        calculated_sig = HMAC.new(current_key, key_enc, digestmod=SHA3_512).hexdigest()
        k1 = multi_decrypt(key_enc, current_key)
        decrypted_data = multi_decrypt(enc_data, k1)
        decompressed = zlib.decompress(decrypted_data)
        code_obj = marshal.loads(decompressed)
        exec(code_obj)
    except:print(False)
if __name__ == "__main__": {module_name}_run()
"""

        temp_dir = tempfile.mkdtemp()
        loader_file = os.path.join(temp_dir, f'{module_name}.py')
        with open(loader_file, 'w', encoding='utf-8') as f:
            f.write(loader_code)
        export_dir = "/sdcard/Download" if os.path.exists("/sdcard") else os.getcwd()
        os.makedirs(export_dir, exist_ok=True)
        so_output = os.path.join(temp_dir, f"{module_name}.so")
        if compile_with_cython(loader_file, so_output):''
        else:
            elf_output = os.path.join(temp_dir, module_name)
            if compile_to_elf(loader_file, elf_output):
                so_output = elf_output
            else:
                try:
                    c_path = loader_file[:-3] + '.c'
                    o_path = loader_file[:-3] + '.o'
                    subprocess.run([sys.executable, "-m", "cython", "--embed", "-3", "-o", c_path, loader_file], check=True, timeout=300)
                    inc_flags, ld_flags = _py_flags()
                    compile_result = _gcc(["-fPIE", "-fPIC", "-O3", *inc_flags, "-c", c_path, "-o", o_path])
                    if compile_result is None: raise Exception("فشل التجميع")
                    link_result = _gcc(["-shared", "-s", o_path, "-o", so_output, *ld_flags])
                    if link_result is None: raise Exception("فشل الربط")
                except Exception as e:
                    so_output = loader_file
        output_file = os.path.join(export_dir, os.path.basename(so_output))
        shutil.copy2(so_output, output_file)
        with open(so_output, 'rb') as f:
            so_data = f.read()
        
        zip_temp = tempfile.NamedTemporaryFile(delete=False, suffix='.zip').name
        with zipfile.ZipFile(zip_temp, 'w') as z:
            z.writestr('__main__.py', """import os, sys, zipfile, tempfile, importlib.util as iu
with zipfile.ZipFile(sys.argv[0], 'r') as z: so_data = z.read('PySan.so')
fd, temp_path = tempfile.mkstemp(suffix='.so'); os.close(fd)
with open(temp_path, 'wb') as f: f.write(so_data)
os.chmod(temp_path, 0o755)
spec = iu.spec_from_file_location('SAN', temp_path)
module = iu.module_from_spec(spec)
sys.modules['SAN'] = module
spec.loader.exec_module(module)
if hasattr(module, 'SAN_run'): module.SAN_run()
os.unlink(temp_path)""")
            z.writestr('PySan.so', so_data)
        
        with open(zip_temp, 'rb') as zf:
            zip_data = zf.read()
        zip_base64 = base64.b64encode(zip_data).decode('utf-8')
        launcher_code = f"""A = '.SaN'
import os,sys,base64 as B
C = '{zip_base64}'
"""
        launcher_code += """try:
    open(A,"wb").write(B.b64decode(C))
    os.system(f'python3 {A} {" ".join(sys.argv[1:])}')
except Exception as e: print(e)
finally:
    os.path.exists(A) and os.remove(A)"""
        with open('PySan.py', 'w', encoding='utf-8') as f:
            f.write(launcher_code)
            print('Done Encode - Save in PySan.py')
        
    except Exception as e:
        print(f"حدث خطأ غير متوقع: {e}")
    finally:
        if 'temp_dir' in locals() and os.path.exists(temp_dir):
            shutil.rmtree(temp_dir, ignore_errors=True)
        if 'zip_temp' in locals() and os.path.exists(zip_temp):
            os.unlink(zip_temp)

if __name__ == "__main__":
    main()
