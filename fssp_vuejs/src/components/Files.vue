<script>
import { reactive, ref } from 'vue';
import { useRoute } from 'vue-router';
import store from '../store';
import axios from 'axios';
import download from 'downloadjs';

let DJANGO_API_URL = store.state.DJANGO_API_URL;

let files = reactive([{
        fileName: "File1",
        Date: "2021-10-01",
        Size: "1.2 MB",
        "Share Status": ["User1", "User2"],
        'sharedWith': ['User1', 'User2'],
    }]);

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
            modalOpen: false,
            action: '',
            fileID: '',
            oneTimeShare: false,
            shareTimePeriod: 0,
            username: '',
            fileContent: ref(''),
            showAlert: false,
            alertContent: '',
            alertType: 'info',
            files: files,
            csrftoken: '',
            fileActions: ["Share", "Revoke", "Download", "Delete"],
        }
    },
        methods:{
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
        async submit() {
            await this.getCsrfToken();
            if (this.action === "Revoke") {
                this.revokeAccess();
            } else if (this.action === "Download") {
                this.downloadFile();
            } else if (this.action === "Share") {
                this.shareFile();
            } else if (this.action === "Delete") {
                this.deleteFile();
            }
        },
        async revokeAccess() {
            this.actionLoading = true;
            axios
                .get(DJANGO_API_URL + "revoke_file", {
                    params: {
                    fileID: this.fileID,
                    shared_with: this.username,
                    csrftoken: this.csrftoken,
                },withCredentials: true,})
                .then((response) => {
                    this.actionLoading = false;
                    console.log(response);
                    if (response.data.message === "Unauthorized access") {
                        console.log("Unauthorized access");
                        window.location.href = "/login";
                    } else if ( response.data.message === "Shared File revoked successfully") {
                        this.showAlert = true;
                        this.alertContent = response.data.message;
                        this.alertType = "success"
                        this.getFilesList();
                    } else {
                        this.showAlert = true;
                        this.alertContent = response.data.message;
                        this.alertType = "error"
                        this.getFilesList();
                    }
                })
                .catch((error) => {
                    console.log(error);
                });
        },
        async downloadFile() {
            this.actionLoading = true;
            let resp = axios({
                url: DJANGO_API_URL + "download_file",
                params: {
                    fileID: this.fileID,
                    csrftoken: this.csrftoken,
                },
                method: 'GET',
                responseType: 'blob', 
                withCredentials: true,
                }).then((response) => {
                    console.log(response);
                    const content = response.headers['content-type'];
                    console.log(response.data, 'filename', content);
                    download(response.data, this.files.find(file => file.fileID === this.fileID).fileName, content);
                });
            return resp;
        },
        async shareFile() {
            this.actionLoading = true;
            console.log(this.oneTimeShare, this.shareTimePeriod);
            axios
                .get(DJANGO_API_URL + "share_file", {
                    params: {
                    file_id: this.fileID,
                    shared_with: this.username,
                    one_time_share: this.oneTimeShare,
                    share_time_period: this.shareTimePeriod,
                    csrftoken: this.csrftoken,
                },withCredentials: true,})
                .then((response) => {
                    this.actionLoading = false;
                    console.log(response);
                    if (response.data.message === "Unauthorized access") {
                        console.log("Unauthorized access");
                        window.location.href = "/login";
                    } else if (response.data.message === "File shared successfully") {
                        this.showAlert = true;
                        this.alertContent = response.data.message;
                        this.alertType = "success"
                        this.getFilesList();
                    } else {
                        this.showAlert = true;
                        this.alertContent = response.data.message;
                        this.alertType = "error"
                    }
                })
                .catch((error) => {
                    console.log(error);
                });
        },
        async deleteFile() {
            this.actionLoading = true;
            axios
                .get(DJANGO_API_URL + "delete_file", {params: {
                    fileID: this.fileID,
                    csrftoken: this.csrftoken,
                },withCredentials: true,})
                .then((response) => {
                    this.actionLoading = false;
                    console.log('OK',response);
                    if (response.data.message === "Unauthorized access") {
                        console.log("Unauthorized access");
                        window.location.href = "/login";
                    } else if (response.data.message === "File deleted successfully") {
                        this.showAlert = true;
                        this.alertContent = response.data.message;
                        this.alertType = "success"
                        this.getFilesList();
                    } else {
                        this.showAlert = true;
                        this.alertContent = response.data.message;
                        this.alertType = "error"
                        this.getFilesList();
                    }
                })
                .catch((error) => {
                    console.log(error);
                });
        },
        openModal(action, fileID) {
            this.modalOpen = true;
            this.action = action;
            this.fileID = fileID;
            console.log(this.action, this.fileID);
        },
        closeModal() {
            this.fileContent = '';
            this.showAlert = false;
            this.modalOpen = false;
        },
        async getFilesList() {
            await axios
                .get(DJANGO_API_URL + "list_files", {withCredentials: true,})
                .then((response) => {
                    console.log(response);
                    if (response.data.message === "Unauthorized access") {
                        console.log("Unauthorized access");
                        window.location.href = "/login";
                    } else {
                        this.files = response.data.files
                        this.isLoading = false;
                        console.log("GG:",this.files );
                    }
                })
                .catch((error) => {
                    console.log(error);
                });
        
        }
    },
    created() {
        this.getFilesList();
    },
}
</script>

<template>
    <div class="container ml-10">
        <v-overlay :model-value="isLoading" class="align-center justify-center">
            <v-progress-circular
                v-if="isLoading"
                indeterminate
                color="white"
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

                <!-- V-Card for the Share functionality -->
                <v-card v-if="action=='Share' && fileID!=''" >
                    <v-card-title>
                        Share the file
                    </v-card-title>
                    <v-card-text>
                        <!-- Input username -->
                        <v-text-field 
                            v-model="username"
                            label="Username"
                            required
                        ></v-text-field>
                        <!-- Share period (in minutes) maybe a counter -->
                            <!-- Validity period counter -->
                        <input  type="number" :min="5" :max="10080" :step="5" placeholder="Validity period (in minutes)" 
                                v-if="!oneTimeShare" v-model="shareTimePeriod" style="width: 100%; padding: 10px; margin: 10px 0; border: 1px solid #ccc; border-radius: 4px; box-sizing: border-box;" >
                    
                        <!-- One time share -->
                        <v-checkbox
                            v-model="oneTimeShare"
                            label="One time share"
                        ></v-checkbox>
                    </v-card-text>
                    <v-card-actions>
                        <v-btn color="warning" @click="closeModal">Close</v-btn>
                        <v-btn color="primary" @click="submit" >
                            {{action}}
                        </v-btn>
                    </v-card-actions>
                    <v-alert class="mt-3" v-if="showAlert" :type="alertType" closable @input="showAlert = false" >{{alertContent}}</v-alert>
                </v-card>

                <!-- V-Card for The Revoke Functionality -->
                <v-card v-if="action=='Revoke' && fileID!=''" >
                    <v-card-title>
                        Revoke a user's access to this file
                    </v-card-title>
                    <v-card-text>
                        <!-- Input username -->
                        <v-text-field
                            v-model="username"
                            label="Username"
                            required
                        ></v-text-field>
                    </v-card-text>
                    <v-card-actions>
                        <v-btn color="warning" @click="closeModal">Close</v-btn>
                        <v-btn color="primary" @click="submit">{{action}}</v-btn>
                    </v-card-actions>
                    <v-alert class="mt-3" v-if="showAlert" :type="alertType" closable @input="showAlert = false" >{{alertContent}}</v-alert>
                </v-card>

                <!-- V-Card for the Download functionality -->
                <v-card v-if="action=='Download' && fileID!=''" >
                    <v-card-title>
                        Download the file
                    </v-card-title>
                    <v-card-text>
                    </v-card-text>
                    <v-card-actions>
                        <v-btn color="warning" @click="closeModal">Close</v-btn>
                        <v-btn color="primary" @click="submit" >
                            {{action}}
                        </v-btn>
                    </v-card-actions>
                    <v-alert class="mt-3" v-if="showAlert" :type="alertType" closable @input="showAlert = false" >{{alertContent}}</v-alert>
                </v-card>

                <!-- V-Card for the Delete functionality -->
                <v-card v-if="action=='Delete' && fileID!=''" >
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
        <v-layout v-if="!isLoading" wrap fluid style="overflow-y: auto;" class="flex-column">
            <v-flex xs12 sm6 md6 lg1 style="height: 350px;" v-for="file in files" :key="file.fileID">
                <v-card v-if="files.SharedWith != ''" style="height: 280px;width: 750px" variant="outlined" flat color="#aac7e8" class="yellow-card d-flex ma-7 pa-8 text-center d-block rounded-lg elevation-15 mx-auto">
                    <v-card-text class="flex-column d-flex align-center justify-center mt-4" color="light-blue lighten-4">
                        <div style="width: 45vh;overflow-y: auto;">
                            <div class="d-flex mb-2">
                                <div class="subheading mx-5"><v-icon left>mdi-book</v-icon><v-chip color="primary"> Filename </v-chip></div>
                                <div class="text">{{ file.fileName }}</div>
                            </div>
                            <div class="d-flex my-2">
                                <div class="text mx-5"><v-icon left>mdi-calendar</v-icon><v-chip color="primary">Creation Date</v-chip></div>
                                <div class="text">{{ file.dateTimeCreated }}</div>
                            </div>
                            <div class="d-flex my-2">
                                <div class="text mx-5"><v-icon left>mdi-scale</v-icon><v-chip color="primary">Size</v-chip></div>
                                <div class="text">{{ file.size }} Bytes</div>
                            </div>
                            <div class="d-flex mu-2">
                                <div class="text mx-5"><v-icon left>mdi-share</v-icon><v-chip color="primary">Share Status</v-chip></div>
                                <div class="text" v-if="(file.sharedWith.length === 0)">Private</div>
                                <div class="text" v-else>
                                    <p><strong><u>Shared with</u></strong></p><br>
                                    <div v-for="item in file.sharedWith" :key="item">{{ item }}</div>
                                </div>
                            </div>
                        </div>
                    </v-card-text>
                    <div class="flex-column">
                        <v-card-actions v-for="action in fileActions" :key="action">
                            <v-btn @click="openModal(action,file.fileID)" class="elevation-5 md-1 mx-3" style="width: 150px;" variant="outlined" flat color="primary">
                                <span>{{ action }} </span>
                            </v-btn>
                        </v-card-actions>
                    </div>
                </v-card>
            </v-flex>
        </v-layout>
    </div>
</template>

<style>
.yellow-card {
    background-color: #01091a;
    border-color: #aac7e8   ;
}

</style>