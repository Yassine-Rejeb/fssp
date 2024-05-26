from flask import Flask, request, Response, send_file, jsonify
import tempfile
from KubernetesManager import KubeManager as km

app = Flask(__name__)

kubeManager = km()
# kubeManager.create_pod()

@app.route('/')
def hello():
    return jsonify({'message': 'Welcome to Kubernetes manager for FSSP'}), 200

@app.route('/upload_file', methods=['POST'])
# Get the file, filename, owner's username & file hash from the request
def upload_file():
    file = request.files['file']
    filename = request.form['filename']
    username = request.form['username']
    original_hash = request.form['file_hash']

    # Display the file's content
    f=file.read().decode()
    # Get the file size
    size=len(f)

    # Select a PV to upload the file to
    pv_pod = kubeManager.select_pv_pod(pods=kubeManager.list_pods(), file_size=size)

    # If no PV is available, create a new one
    if pv_pod == None:
        kubeManager.create_pod()
        pv_pod = kubeManager.select_pv_pod(pods=kubeManager.list_pods(), file_size=size)

    # Check params before calling the upload_file method
    # print(f'filename: {filename}, username: {username}, original_hash: {original_hash}, size: {size}, pv_pod: {pv_pod}')
    
    # Upload the file to the selected PV
    result = kubeManager.upload_file(f, filename, username, pv_pod, original_hash)
    # print('result:', result)
    # Check if the file was uploaded successfully
    if result:
        return jsonify({'message': 'File uploaded successfully', 'podname': kubeManager.get_pod_name(filename=filename , username=username, namespace='default' )}), 200
    else:
        return jsonify({'message': 'Integrity check failed, file was not uploaded'}), 500

@app.route('/get_file', methods=['GET'])
# Get the name, owner's username and pod's name from the request
def get_file():
    filename = request.args.get('filename')
    username = request.args.get('owner')
    PodName = request.args.get('pod_name')
    # print(f'filename: {filename}, username: {username}, pod_name: {PodName}')

    # Check if the file exists
    file_exists = kubeManager.file_exists(filename, username, PodName)
    if not file_exists:
        return jsonify({'message': 'File not found'}), 404

    # Get the file content
    file_content = kubeManager.get_file_content(filename=filename, username=username, pod_name=PodName)

    # Create a tempfile for the file response
    with tempfile.NamedTemporaryFile() as temp:
        temp.write(file_content.encode())
        temp.seek(0)
        return send_file(temp.name, as_attachment=True) #, attachment_filename=filename)
    return jsonify({'message': 'File retrieved successfully'}), 200

@app.route('/delete_file', methods=['DELETE'])
# Get the name, owner's username and pod's name from the request
def delete_file():
    data = request.get_json()
    filename = data.get('filename')
    username = data.get('owner')
    PodName = data.get('pod_name')
    # print(f'filename: {filename}, username: {username}, pod_name: {PodName}')

    # Check if the file exists
    pre_delete_check = kubeManager.file_exists(filename, username, PodName)
    if not pre_delete_check:
        return jsonify({'message': 'File not found'}), 404

    # Delete the file
    kubeManager.delete_file(filename, username, PodName)

    # Check if the file was deleted successfully
    post_delete_check = kubeManager.file_exists(filename, username, PodName)
    if not post_delete_check:
        return jsonify({'message': 'File deleted successfully'}), 200
    else:
        return jsonify({'message': 'Failed to delete the file'}), 500

# Use gunicorn to run the app
if __name__ == '__main__':
    app.run(host='0.0.0.0', port=80)
    