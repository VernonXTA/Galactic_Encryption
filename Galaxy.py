import numpy as np
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
import os
import base64

def full_galactic_measurement():
    radialDistanceLY = 50000  # Light-years
    maxHeight = 500  # Light-years
    num_arms = 4
    arm_separation = 2 * np.pi / num_arms

    spiral_arm_spread = 1000  # Light-years
    clustersAmount = 5000

    densityOfClusters = clustersAmount / (np.pi * radialDistanceLY**2)  # Clusters per square light-year

    radial_distance = np.sqrt(np.random.uniform(0, radialDistanceLY**2))
    height = np.random.uniform(-maxHeight, maxHeight)
    base_angle = np.random.uniform(0, 2 * np.pi)
    arm_number = np.random.randint(0, num_arms)
    theta_arm = base_angle + arm_number * arm_separation + np.random.normal(0, spiral_arm_spread / radial_distance)
    
    # Adding cluster influence
    theta = theta_arm + densityOfClusters * np.random.uniform(0, radial_distance)

    # Convert to Cartesian coordinates
    x = radial_distance * np.cos(theta)
    y = radial_distance * np.sin(theta)
    z = height

    return x, y, z

try:
    galaxy_coordinates = full_galactic_measurement()
    print(f"Random Coordinates in the Milky Way (light-years): {galaxy_coordinates[0]:.2f}, {galaxy_coordinates[1]:.2f}, {galaxy_coordinates[2]:.2f} \n Raw Coordinates: {galaxy_coordinates}")
except Exception as e:
    print(f"[!] Could not calculate coordinates due to error: {e}")

# Convert the x-coordinate to a string for use as a password
password = str(galaxy_coordinates[0])
file_path = r'C:\Users\dante\OneDrive\Desktop\hello.txt'

def derive_key(password: str, salt: bytes) -> bytes:
    """Derive a Fernet-compatible key from a password and salt."""
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
    return key

def encrypt_file():
    """Encrypt the file specified by file_path."""
    salt = os.urandom(16)

    key = derive_key(password, salt)
    fernet = Fernet(key)

    with open(file_path, 'rb') as file:
        data = file.read()

    encrypted_data = fernet.encrypt(data)

    with open(file_path + '.enc', 'wb') as file:
        file.write(salt + encrypted_data)

    print(f"File has been encrypted and saved as {file_path}.enc")

def decrypt_file(encrypted_file_path: str):
    """Decrypt a file using Fernet encryption with a derived key."""
    with open(encrypted_file_path, 'rb') as file:
        data = file.read()

    salt = data[:16]
    encrypted_data = data[16:]

    key = derive_key(password, salt)
    fernet = Fernet(key)

    decrypted_data = fernet.decrypt(encrypted_data)

    decrypted_file_path = encrypted_file_path.rsplit('.enc', 1)[0]
    with open(decrypted_file_path, 'wb') as file:
        file.write(decrypted_data)

    print(f'File decrypted and saved as {decrypted_file_path}')

# Call encrypt_file and decrypt_file for testing
encrypt_file()
decrypt_file(file_path + '.enc')
