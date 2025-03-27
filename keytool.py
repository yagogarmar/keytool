import argparse
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization, hashes
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import os
from datetime import datetime, timedelta, UTC
import getpass  # Para solicitar la contraseña de manera segura
import pickle


# python keytool.py genkey -a mi_clave -s 4096 -f mi_keystore.pkl                     <- Generar un un par de llaves asimetricas 
# python keytool.py exportcert -a mi_clave -o mi_certificado.crt -f mi_keystore.pkl   <- Exportar certificado de un keystore
# python keytool.py importcert -a mi_clave -i mi_certificado.crt -f mi_keystore.pkl   <- Importar un certificado 
# python keytool.py list -f mi_keystore.pkl                                           <- Listar entradas keystore


# Simulación de un keystore
keystore = {}

# Función para derivar una clave a partir de una contraseña
def derive_key(password, salt):
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,  # 32 bytes = 256 bits (tamaño de clave para AES-256)
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    return kdf.derive(password.encode())

# Función para encriptar datos
def encrypt_data(data, password):
    salt = os.urandom(16)  # Generar un salt aleatorio
    key = derive_key(password, salt)
    iv = os.urandom(16)  # Vector de inicialización para AES
    cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    encrypted_data = encryptor.update(data) + encryptor.finalize()
    return salt + iv + encrypted_data  # Concatenar salt, IV y datos encriptados

# Función para desencriptar datos
def decrypt_data(encrypted_data, password):
    salt = encrypted_data[:16]  # Los primeros 16 bytes son el salt
    iv = encrypted_data[16:32]  # Los siguientes 16 bytes son el IV
    key = derive_key(password, salt)
    cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    return decryptor.update(encrypted_data[32:]) + decryptor.finalize()  # Desencriptar el resto

# Función para generar un par de claves y un certificado autofirmado
def generate_key_pair(key_size, alias, keystore_file, password):
    # Cargar el keystore existente si existe
    existing_keystore = {}
    if os.path.exists(keystore_file):
        existing_keystore = load_keystore(keystore_file, password)
        if existing_keystore is None:
            return  # Error al cargar el keystore existente
    
    # Verificar si el alias ya existe
    if existing_keystore and alias in existing_keystore:
        print(f"Error: El alias '{alias}' ya existe en el keystore.")
        return

    # Generar la clave privada
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=key_size,
    )

    # Extraer la clave pública
    public_key = private_key.public_key()

    # Crear un certificado autofirmado
    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "California"),
        x509.NameAttribute(NameOID.LOCALITY_NAME, "San Francisco"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "My Company"),
        x509.NameAttribute(NameOID.COMMON_NAME, f"{alias}.mycompany.com"),  # Incluir alias en el CN
    ])

    certificate = x509.CertificateBuilder().subject_name(
        subject
    ).issuer_name(
        issuer
    ).public_key(
        public_key
    ).serial_number(
        x509.random_serial_number()
    ).not_valid_before(
        datetime.now(UTC)
    ).not_valid_after(
        datetime.now(UTC) + timedelta(days=365)
    ).sign(private_key, hashes.SHA256())

    # Serializar y guardar la clave privada
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )

    # Serializar y guardar la clave pública
    public_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    # Serializar y guardar el certificado
    cert_pem = certificate.public_bytes(serialization.Encoding.PEM)

    # Inicializar el keystore si no existe
    if not existing_keystore:
        existing_keystore = {}

    # Añadir las claves y el certificado al keystore
    existing_keystore[alias] = {
        "private_key": private_pem,
        "public_key": public_pem,
        "certificate": cert_pem
    }

    # Serializar el keystore
    keystore_data = pickle.dumps(existing_keystore)

    # Encriptar el keystore
    encrypted_keystore = encrypt_data(keystore_data, password)

    # Guardar el keystore encriptado en un archivo
    with open(keystore_file, "wb") as f:
        f.write(encrypted_keystore)

    print(f"Par de claves y certificado generados y almacenados en el keystore bajo el alias '{alias}'.")

# Función para cargar el keystore desencriptado
def load_keystore(keystore_file, password):
    if not os.path.exists(keystore_file):
        print("El keystore no existe.")
        return None

    # Leer el keystore encriptado
    with open(keystore_file, "rb") as f:
        encrypted_keystore = f.read()

    # Desencriptar el keystore
    try:
        keystore_data = decrypt_data(encrypted_keystore, password)
        return pickle.loads(keystore_data)
    except Exception as e:
        print("Error al desencriptar el keystore. ¿Contraseña incorrecta?")
        return None

# Función para exportar un certificado
def export_certificate(alias, cert_file, keystore_file, password):
    keystore = load_keystore(keystore_file, password)
    if not keystore:
        return

    if alias not in keystore:
        print(f"Alias '{alias}' no encontrado en el keystore.")
        return

    cert_pem = keystore[alias]["certificate"]
    with open(cert_file, "wb") as f:
        f.write(cert_pem)

    print(f"Certificado exportado a '{cert_file}'.")

# Función para importar un certificado
def import_certificate(alias, cert_file, keystore_file, password):
    keystore = load_keystore(keystore_file, password)
    if not keystore:
        return

    if alias not in keystore:
        print(f"Alias '{alias}' no encontrado en el keystore.")
        return

    with open(cert_file, "rb") as f:
        cert_pem = f.read()

    keystore[alias]["certificate"] = cert_pem

    # Serializar y encriptar el keystore
    keystore_data = pickle.dumps(keystore)
    encrypted_keystore = encrypt_data(keystore_data, password)

    # Guardar el keystore encriptado
    with open(keystore_file, "wb") as f:
        f.write(encrypted_keystore)

    print(f"Certificado importado desde '{cert_file}' bajo el alias '{alias}'.")

# Función para listar las entradas del keystore
def list_keystore(keystore_file, password):
    keystore = load_keystore(keystore_file, password)
    if not keystore:
        return

    if not keystore:
        print("El keystore está vacío.")
        return

    print("Entradas en el keystore:")
    for alias, keys in keystore.items():
        print(f"Alias: {alias}")
        print(f"Clave privada: {keys['private_key'].decode()}")
        print(f"Clave pública: {keys['public_key'].decode()}")
        print(f"Certificado: {keys['certificate'].decode()}")
        print("-" * 40)

# Configuración de argumentos de línea de comandos
parser = argparse.ArgumentParser(description="Herramienta para gestionar claves y certificados (simulación de keytool).")
subparsers = parser.add_subparsers(dest="command")

# Subcomando para generar un par de claves y un certificado
gen_parser = subparsers.add_parser("genkey", help="Generar un par de claves y un certificado autofirmado.")
gen_parser.add_argument("-a", "--alias", required=True, help="Alias para la clave.")
gen_parser.add_argument("-s", "--keysize", type=int, default=2048, help="Tamaño de la clave (por defecto: 2048).")
gen_parser.add_argument("-f", "--file", default="keystore.pkl", help="Archivo keystore (por defecto: keystore.pkl).")

# Subcomando para exportar un certificado
export_parser = subparsers.add_parser("exportcert", help="Exportar un certificado.")
export_parser.add_argument("-a", "--alias", required=True, help="Alias de la clave.")
export_parser.add_argument("-o", "--out", required=True, help="Archivo de salida para el certificado.")
export_parser.add_argument("-f", "--file", default="keystore.pkl", help="Archivo keystore (por defecto: keystore.pkl).")

# Subcomando para importar un certificado
import_parser = subparsers.add_parser("importcert", help="Importar un certificado.")
import_parser.add_argument("-a", "--alias", required=True, help="Alias de la clave.")
import_parser.add_argument("-i", "--input", required=True, help="Archivo de entrada para el certificado.")
import_parser.add_argument("-f", "--file", default="keystore.pkl", help="Archivo keystore (por defecto: keystore.pkl).")

# Subcomando para listar el keystore
list_parser = subparsers.add_parser("list", help="Listar las entradas del keystore.")
list_parser.add_argument("-f", "--file", default="keystore.pkl", help="Archivo keystore (por defecto: keystore.pkl).")

# Procesar los argumentos
args = parser.parse_args()

# Solicitar la contraseña
password = getpass.getpass("Introduce la contraseña del keystore: ")

# Ejecutar la acción correspondiente
if args.command == "genkey":
    generate_key_pair(args.keysize, args.alias, args.file, password)
elif args.command == "exportcert":
    export_certificate(args.alias, args.out, args.file, password)
elif args.command == "importcert":
    import_certificate(args.alias, args.input, args.file, password)
elif args.command == "list":
    list_keystore(args.file, password)
else:
    parser.print_help()