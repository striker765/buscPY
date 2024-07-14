from flask import Flask, render_template, request, jsonify
import requests

app = Flask(__name__)

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/search', methods=['POST'])
def search():
    api_key = '9858e80a2593bde69ce0906a6fd1e79a2b0df6c31004fab9f7dbce4d32df12c1'  # Substitua pela sua API key do VirusTotal
    input_value = request.form['searchInput'].strip()

    if not input_value:
        return jsonify({'error': 'Por favor, digite um IP ou site para pesquisar.'}), 400

    url = f'https://www.virustotal.com/api/v3/ip_addresses/{input_value}'
    headers = {'x-apikey': api_key}

    try:
        response = requests.get(url, headers=headers)
        response.raise_for_status()
        data = response.json()
        return jsonify(data), 200
    except requests.exceptions.RequestException as e:
        return jsonify({'error': f'Erro na requisição: {str(e)}'}), 500

if __name__ == '__main__':
    app.run(debug=True)
