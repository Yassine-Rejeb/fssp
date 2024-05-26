from kubernetes import client, config, stream
import time

class KubeManager:
    def __init__(self):
        # Load the in-cluster configuration
        config.load_incluster_config()
        # config.load_kube_config()
        # Create an instance of the API class
        self.api_instance = client.CoreV1Api()
    
    # List all the PVs by names
    def list_pvs(self, namespace="default", starts_with="k8s-manager-pv"):
        pv_list = self.api_instance.list_persistent_volume()
        result = []
        for pv in pv_list.items:
            if pv.metatdata.name.startswith(starts_with):
                result.append(pv)
        return result

    # List all the Pods by names
    def list_pods(self, namespace="default", starts_with="k8s-manager-pod"):
        pod_list = self.api_instance.list_namespaced_pod(namespace=namespace)
        result = []
        for pod in pod_list.items:
            if pod.metadata.name.startswith(starts_with):
                result.append(pod)
        return result

    # Select a pv to upload the file to
    def select_pv_pod(self, namespace='default', file_size=None, pods=None):
        # If pods is an empty list, return None tp instigate the creation of a new pod
        if len(pods) == 0:
            return None

        resp = []
        for i in pods:
            # Execute the command to get the size of the filesystem in a specific path

            # The command is: df -h /path
            command = ["du", "-sh", "/mnt/fssp_files"]

            pod_name = i.metadata.name

            try:
                cmd_reslt = stream.stream(self.api_instance.connect_get_namespaced_pod_exec, pod_name, namespace,
                                    command=command,
                                    stderr=True, stdin=False,
                                    stdout=True, tty=False).split()[0]
                used_bytes = 0.0
                if cmd_reslt.endswith('K'):
                    used_bytes = float(cmd_reslt[:-1]) * 1024
                elif cmd_reslt.endswith('M'):
                    used_bytes = float(cmd_reslt[:-1]) * 1024 * 1024
                resp.append({'pod': pod_name, 'pv': i.spec.volumes[0].name, 'size': used_bytes})
                # print(used_bytes)
            except Exception as e:
                print(f'Failed to execute command in pod {pod_name}: {e}')

        # Sort the list by size in ascending order
        resp.sort(key=lambda x: x['size'])

        for i in resp:
            # Check if the PV has enough space to store the file (Max size is 500MB)
            if i['size'] + file_size < 500 * 1024 * 1024:
                return i

    # Create a pod, a pv and a pvc to store the file
    def create_pod(self, namespace='default', pv_name='k8s-manager-pv', pvc_name='k8s-manager-pvc', pod_name='k8s-manager-pod'):
        uniq = str(str(time.time()).replace(".", ""))

        # Create a PV
        pv = client.V1PersistentVolume(
            api_version="v1",
            kind="PersistentVolume",
            metadata=client.V1ObjectMeta(name=pv_name+'-'+uniq),
            spec=client.V1PersistentVolumeSpec(
                capacity={"storage": "500Mi"},
                access_modes=["ReadWriteOnce"],
                host_path=client.V1HostPathVolumeSource(path="/mnt/fssp_files")
            )
        )
        self.api_instance.create_persistent_volume(body=pv)
        
        # Create a PVC
        pvc = client.V1PersistentVolumeClaim(
            api_version="v1",
            kind="PersistentVolumeClaim",
            metadata=client.V1ObjectMeta(name=pvc_name+'-'+uniq),
            spec=client.V1PersistentVolumeClaimSpec(
                access_modes=["ReadWriteOnce"],
                resources=client.V1ResourceRequirements(requests={"storage": "500Mi"}),
                volume_name=pv_name+'-'+uniq
            )
        )
        self.api_instance.create_namespaced_persistent_volume_claim(namespace=namespace, body=pvc)
        
        # Create a Pod
        pod = client.V1Pod(
            api_version="v1",
            kind="Pod",
            metadata=client.V1ObjectMeta(name=pod_name+'-'+uniq),
            spec=client.V1PodSpec(
                containers=[
                    client.V1Container(
                        name="k8s-manager-container"+"-"+uniq,
                        image="busybox",
                        volume_mounts=[client.V1VolumeMount(mount_path="/mnt/fssp_files", name=pv_name+'-'+uniq)],
                        command=["/bin/sh", "-c", "tail -f /dev/null"]
                    )
                ],
                volumes=[client.V1Volume(name=pv_name+'-'+uniq, persistent_volume_claim=client.V1PersistentVolumeClaimVolumeSource(claim_name=pvc_name+'-'+uniq))]
            )
        )
        self.api_instance.create_namespaced_pod(namespace=namespace, body=pod)
        return pod

    # Save the file to the selected PV
    def upload_file(self, file, filename, username, pv_pod, hashed, namespace='default'):
        # Get the pod name
        pod_name = pv_pod['pod']

        # Make sure the owner has a directory in the PV
        command = ["mkdir", "-p", "/mnt/fssp_files/"+username]

        # Execute the command
        try:
            stream.stream(self.api_instance.connect_get_namespaced_pod_exec, pod_name, namespace,
                            command=command,
                            stderr=True, stdin=False,
                            stdout=True, tty=False)
        except Exception as e:
            print(f'Failed to execute command in pod {pod_name}: {e}')
        
        # Command to save the file in the PV
        command = ["sh", "-c", f'echo "{file[:-1]}" > /mnt/fssp_files/{username}/{filename}']

        # Execute the command
        try:
            r = stream.stream(self.api_instance.connect_get_namespaced_pod_exec, pod_name, namespace,
                            command=command,
                            stderr=True, stdin=False,
                            stdout=True, tty=False)
        except Exception as e:
            print(f'Failed to execute command in pod {pod_name}: {e}')

        # Check if the file was saved successfully via getting its hash and comparing it with the original file's hash
        command = ["md5sum", "/mnt/fssp_files/"+username+"/"+filename]

        # Execute the command
        try:
            file_hash = stream.stream(self.api_instance.connect_get_namespaced_pod_exec, pod_name, namespace,
                            command=command,
                            stderr=True, stdin=False,
                            stdout=True, tty=False).split()[0]
        except Exception as e:
            print(f'Failed to execute command in pod {pod_name}: {e}')
                
        # print(f'file_hash: {file_hash}',"\n",f' hashed: {hashed}')
        return True
        # if file_hash != hashed:
        #     # Delete the file
        #     self.delete_file(filename, username, pod_name, namespace)
        #     return False
        # else:
        #     return True

    # Get the file
    def get_file_content(self, filename="", username="", pod_name="", namespace='default'):
        
        # Execute the command to get the file content
        command = ["cat", "/mnt/fssp_files/"+username+"/"+filename]

        # Execute the command
        try:
            file_content = stream.stream(self.api_instance.connect_get_namespaced_pod_exec, pod_name, namespace,
                            command=command,
                            stderr=True, stdin=False,
                            stdout=True, tty=False)
            # print(file_content)
        except Exception as e:
            print(f'Failed to execute command in pod {pod_name}: {e}')

        return file_content
    
    # Get the podNme of a file
    def get_pod_name(self, filename="", username="", namespace='default'):
        # Get pods names
        pods = self.list_pods(namespace=namespace)
        podnames = []
        for pod in pods:
            podnames.append(pod.metadata.name)

        # Check if the file exists
        for pod in podnames:
            if self.file_exists(filename, username, pod, namespace):
                return pod

        return None

    # Check if the file exists
    def file_exists(self, filename, username, pod_name, namespace='default'):
        # Execute the command to check if the file exists
        command = ["ls", "/mnt/fssp_files/"+username+"/"+filename]

        # Execute the command
        try:
            file_check = stream.stream(self.api_instance.connect_get_namespaced_pod_exec, pod_name, namespace,
                            command=command,
                            stderr=True, stdin=False,
                            stdout=True, tty=False)
            print(file_check[:-1])
            if file_check[:-1] == f"/mnt/fssp_files/{username}/{filename}":
                return True
            
            return False

        except Exception as e:
            print(f'Failed to execute command in pod {pod_name}: {e}')
    
    # Delete the file
    def delete_file(self, filename, username, pod_name, namespace='default'):
        # Execute the command to delete the file
        command = ["rm", "-f", "/mnt/fssp_files/"+username+"/"+filename]

        # Execute the command
        try:
            stream.stream(self.api_instance.connect_get_namespaced_pod_exec, pod_name, namespace,
                            command=command,
                            stderr=True, stdin=False,
                            stdout=True, tty=False)
        except Exception as e:
            print(f'Failed to execute command in pod {pod_name}: {e}')
        
        # Command to check if the file was deleted
        command = ["ls", "/mnt/fssp_files/"+username+"/"+filename]
