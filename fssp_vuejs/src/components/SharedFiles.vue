<script>
import { reactive, ref } from 'vue';
import { useRoute } from 'vue-router'
import axios from 'axios';
import download from 'downloadjs';
import store from '../store';

let DJANGO_API_URL = store.state.DJANGO_API_URL;

let files = reactive([{
    "FileName": "",
    "DatetimeShared": "",
    "OwnerFullname": "",
    "OwnerUsername": "",
    "FileID": "",
}])

export default {
    setup() {
        const route = useRoute()
        const currentUrl = route.fullPath
        console.log(currentUrl);
        return {
        currentUrl,
        }
    },
    data() {
        return {
            actionLoading: ref(false),
            isLoading: ref(true),
            files,
            thereAreFiles: ref(false),
            modalOpen: false,
            action: '',
            FileID: '',
            FileContent: ref(''),
            showAlert: false,
            alertContent: '',
            alertType: 'info',
            csrftoken: '',
            FileActions: ["Download", "Delete"],
            }
    },
    async mounted() {
        // this.listSharedFiles();
        setInterval(() => {
            this.listSharedFiles();
        }, 1000);
    },
    methods: {
        async getCsrfToken() {
            let resp = axios
                .get(DJANGO_API_URL + "get_csrf_token", {withCredentials: true,})
                .then((response) => {
                    this.csrftoken = response.data.csrftoken;
                })
                .catch((error) => {
                    console.log(error);
                });
            return resp;
        },
        async listSharedFiles(){
            let resp = await axios
                .get(DJANGO_API_URL + "list_shared_files", {withCredentials: true,})
                .then((response) => {
                    console.log("Let's check:",response);
                    if (response.data.message === "Unauthorized access") {
                        console.log("Unauthorized access");
                        window.location.href = "/login";
                    } else if (response.data.message === "Success" && response.data.files === []) {
                        this.isLoading = false;
                        this.thereAreFiles = false;
                        console.log("No files found");
                    } else if (response.data.message === "Success" && response.data.files !== []) {
                        // Check if there is any change in the files
                        if (JSON.stringify(files) === JSON.stringify(response.data.files)) {
                            this.isLoading = false;
                        }else {
                            // Update the files
                            this.files = reactive([{
                                "FileName": "",
                                "DatetimeShared": "",
                                "OwnerFullname": "",
                                "OwnerUsername": "",
                                "size": "",
                                "FileID": "",
                            }]);

                            for (let key in response.data.files) {
                                this.files[key] = response.data.files[key];
}
                            this.isLoading = false;
                            if (this.files.length > 0 && this.files[0].FileID !== "") {
                                this.thereAreFiles = true;
                            }
                        }
                    }
                })
                .catch((error) => {
                    console.log(error);
                });
            return resp;
        },
        async downloadFile() {
            this.actionLoading = true;
            let resp = axios({
                url: DJANGO_API_URL + "download_shared_file",
                params: {
                    fileID: this.FileID,
                    csrftoken: this.csrftoken,
                },
                method: 'GET',
                responseType: 'blob', 
                withCredentials: true,
                }).then((response) => {
                    console.log(response);
                    const content = response.headers['content-type'];
                    console.log(response.data, 'filename', content);
                    download(response.data, this.files.find(file => file.FileID === this.FileID).FileName, content);
                });
            return resp;
        },
        async removeAccessToFile() {
            this.actionLoading = true;
            let resp = await axios
                .get(DJANGO_API_URL + "remove_access_to_file", {params: {
                    fileID: this.FileID,
                    csrftoken: this.csrftoken,
                }, withCredentials: true,})
                .then((response) => {
                    console.log(response);
                    if (response.data.message === "Shared File Revoked Successfully") {
                        this.showAlert = true;
                        this.alertContent = "Access removed successfully";
                        this.alertType = "success";
                        this.actionLoading = false;
                        this.isLoading = true;
                        this.thereAreFiles = false;
                        this.listSharedFiles();
                    } else {
                        this.showAlert = true;
                        this.alertContent = response.data.message;
                        this.alertType = "error";
                        this.actionLoading = false;
                        this.listSharedFiles();
                    }
                }).catch((error) => {
                    console.error(error);
                });
            return resp;
        },
        openModal(action, fileID) {
            this.modalOpen = true;
            this.action = action;
            this.FileID = fileID;
        },
        closeModal() {
            this.modalOpen = false;
            this.action = '';
            this.file_id = '';
            this.fileContent = '';
            this.showAlert = false;
            this.alertContent = '';
            this.alertType = 'info';
            this.isLoading = true;
            this.listSharedFiles();
        },
        async submit() {
            await this.getCsrfToken();
            if (this.action === 'Download') {
                this.downloadFile();
            } else if (this.action === 'Delete') {
                this.removeAccessToFile();
                }
            }
        }
    }
</script>

<template>
 <div class="container ml-10">
    <v-overlay :model-value="isLoading" class="align-center justify-center">
        <v-progress-circular
            v-if="isLoading"
            indeterminate
            color="primary"
        ></v-progress-circular>
    </v-overlay>
    <v-container>
            <v-overlay :model-value="actionLoading" class="align-center justify-center" :style="{ 'width': '500px', 'height': '500px' }">
                <v-progress-circular
                    v-if="isLoading"
                    indeterminate
                    color="primary"
                ></v-progress-circular>
            </v-overlay>
        <v-dialog v-model="modalOpen" max-width="500px">
            <!-- V-Card for the Download functionality -->
            <v-card v-if="action=='Download' && file_id!=''" >
                <v-card-title>
                    Download The File
                </v-card-title>
                <v-card-actions>
                    <v-btn color="warning" @click="closeModal">Close</v-btn>
                    <v-btn color="primary" @click="submit" >
                        {{action}}
                    </v-btn>
                </v-card-actions>
                <v-alert class="mt-3" v-if="showAlert" :type="alertType" closable @input="showAlert = false" >{{alertContent}}</v-alert>
            </v-card>

            <!-- V-Card for the Delete functionality -->
            <v-card v-if="action=='Delete' && file_id!=''" >
                <v-card-title>
                    Delete the file
                </v-card-title>
                <v-card-text>
                    Are you sure you want to delete this file?
                </v-card-text>
                <v-card-actions>
                    <v-btn color="warning" @click="closeModal">Close</v-btn>
                    <v-btn color="primary" @click="submit">{{action}}</v-btn>
                </v-card-actions>
                <v-alert class="mt-3" v-if="showAlert" :type="alertType" closable @input="showAlert = false" >{{alertContent}}</v-alert>
            </v-card>
        </v-dialog>
    </v-container>
    <v-container v-if="thereAreFiles" >
        <v-layout v-if="!isLoading" wrap fluid style="overflow-y: auto;" class="flex-column">
            <v-flex xs12 sm6 md6 lg1 style="height: 350px;" 
            v-for="secret in files" :key="secret.FileID" >
                <v-card style="height: 280px;width: 750px"
                variant="outlined" flat color="#aac7e8" class="yellow-card d-flex
                ma-7 pa-8 text-center d-block rounded-lg elevation-15 mx-auto">
                    <v-card-text class="flex-column d-flex align-center justify-center mt-4" color="light-blue lighten-4">
                        <div style="width: 45vh;overflow-y: auto;">
                            <div class="d-flex mb-2">
                            <div class="subtitle-1 mx-5"><v-icon left>mdi-book</v-icon><v-chip color="primary">File Name</v-chip></div>
                            <div class="text">{{ secret.FileName }}</div>
                            </div>
                            <div class="d-flex my-2">
                            <div class="subtitle-2 mx-5"><v-icon left>mdi-account</v-icon><v-chip color="primary">File Owner</v-chip></div>
                            <div class="text">{{ secret.OwnerFullname }} ( <strong>Username:</strong> {{ secret.OwnerUsername }})</div>
                            </div>
                            <div class="d-flex mu-2">
                            <div class="subtitle-2 mx-5"><v-icon left>mdi-calendar</v-icon><v-chip color="primary">Share Date</v-chip></div>
                            <div class="text">{{ secret.DatetimeShared }}</div>
                            </div>
                            <!-- file size -->
                            <div class="d-flex my-2">
                            <div class="subtitle-2 mx-5"><v-icon left>mdi-file</v-icon><v-chip color="primary">File Size</v-chip></div>
                            <div class="text">{{ secret.size }} Bytes</div>
                            </div>
                        </div>
                    </v-card-text>
                    <div class="flex-column d-flex align-center justify-center">
                        <v-card-actions v-for="action in FileActions" :key="action">
                            <v-btn @click="openModal(action,secret.FileID)" class="elevation-5 md-1 mx-3" style="width: 150px;" variant="outlined" flat color="primary">
                                <span>{{ action }}</span>
                            </v-btn>
                        </v-card-actions>
                    </div>
                </v-card>
            </v-flex>
        </v-layout>
    </v-container>
</div>
</template>

<style>
.yellow-card {
    background-color: #01091a;
    border-color: #aac7e8   ;
}

</style>