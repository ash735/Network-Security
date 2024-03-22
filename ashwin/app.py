from flask import Flask, render_template, request
from Crypto.PublicKey import RSA


from Crypto.Cipher import PKCS1_OAEP
import base64

app = Flask(__name__)
app.secret_key = b'_5#y2L"F4Q8z\n\xec]/'

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/generate_keys')
def generate_keys():
    # Generate an RSA key pair
    key = RSA.generate(2048)

    # Save the private key in session (should be stored securely in a real application)
    private_key = key.export_key().decode('utf-8')
    public_key = key.publickey().export_key().decode('utf-8')

    return render_template('key_generation.html', private_key = private_key, public_key = public_key)

@app.route('/encrypt', methods=['POST'])
def encrypt():
    plaintext = request.form['plaintext']
    public_key = request.form['public_key']

    # Load the public key
    key = RSA.import_key(public_key)

    # Use PKCS1_OAEP padding scheme
    cipher = PKCS1_OAEP.new(key)

    # Encrypt the data
    ciphertext = base64.b64encode(cipher.encrypt(plaintext.encode('utf-8'))).decode('utf-8')

    return render_template('result.html', ciphertext = ciphertext)

@app.route('/decrypt', methods=['POST'])
def decrypt():
    ciphertext = request.form['ciphertext']
    private_key = request.form['private_key']

    # Load the private key
    key = RSA.import_key(private_key)

    # Use PKCS1_OAEP padding scheme
    cipher = PKCS1_OAEP.new(key)

    # Decrypt the data
    decrypted_data = cipher.decrypt(base64.b64decode(ciphertext)).decode('utf-8')

    return render_template('result.html', decrypted_data = decrypted_data)

if __name__ == '__main__':
    app.run(debug=True)