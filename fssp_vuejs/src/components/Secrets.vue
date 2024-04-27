<script>
import { useRoute } from 'vue-router'
import { reactive, ref } from 'vue'
import axios from 'axios';

import store from '../store';

let DJANGO_API_URL = store.state.DJANGO_API_URL;

let secrets = reactive([
    {
        "SecretID": "",
        "SecretName": "",
        "DatetimeCreated": "",
        "SharedWith": ""
    }
]);

export default {
    setup() {
        const route = useRoute()
        const currentUrl = route.fullPath
        // console.log(currentUrl);

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
            secret_id: '',
            oneTimeShare: 0,
            shareTimePeriod: 0,
            username: '',
            secretContent: ref(''),
            showAlert: false,
            alertContent: '',
            alertType: 'info',
            secrets,
            csrftoken: '',
            secretActions: ["Share", "Revoke", "Display", "Delete"],
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
            } else if (this.action === "Display") {
                this.displaySecret();
            } else if (this.action === "Share") {
                this.shareSecret();
            } else if (this.action === "Delete") {
                this.deleteSecret();
            }
        },
        async revokeAccess() {
            this.actionLoading = true;
            axios
                .get(DJANGO_API_URL + "revoke_secret", {
                    params: {
                    secret_id: this.secret_id,
                    username: this.username,
                    csrftoken: this.csrftoken,
                },withCredentials: true,})
                .then((response) => {
                    this.actionLoading = false;
                    console.log(response);
                    if (response.data.message === "Unauthorized access") {
                        console.log("Unauthorized access");
                        window.location.href = "/login";
                    } else if ( response.data.message === "Secret unshared successfully") {
                        this.showAlert = true;
                        this.alertContent = response.data.message;
                        this.alertType = "success"
                        this.getSecretsList();
                    } else {
                        this.showAlert = true;
                        this.alertContent = response.data.message;
                        this.alertType = "error"
                        this.getSecretsList();
                    }
                })
                .catch((error) => {
                    console.log(error);
                });
        },
        async displaySecret() {
            this.actionLoading = true;
            let resp = axios
                .get(DJANGO_API_URL + "display_secret", {params: {
                    secret_id: this.secret_id,
                    csrftoken: this.csrftoken,
                },
                    withCredentials: true,
                })
                .then((response) => {
                    this.actionLoading = false;
                    console.log(response);
                    if (response.data.message === "Unauthorized access") {
                        console.log("Unauthorized access");
                        window.location.href = "/login";
                    } else if (response.data.message === "Secret Retrieved successfully") {
                        this.showAlert = true;
                        this.alertContent = response.data.message;
                        this.alertType = "success"
                        this.secretContent = response.data.secret_content;
                        console.log("Secret Content:", this.secretContent);
                    } else {
                        this.showAlert = true;
                        this.alertContent = response.data.message;
                        this.alertType = "error"
                    }
                })
                .catch((error) => {
                    console.log(error);
                });
                console.log("Secret Content:", this.secretContent);
            return resp;
        },
        async shareSecret() {
            this.actionLoading = true;
            console.log(this.oneTimeShare, this.shareTimePeriod);
            axios
                .get(DJANGO_API_URL + "share_secret", {
                    params: {
                    secret_id: this.secret_id,
                    username: this.username,
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
                    } else if (response.data.message === "Secret shared successfully") {
                        this.showAlert = true;
                        this.alertContent = response.data.message;
                        this.alertType = "success"
                        this.getSecretsList();
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
        async deleteSecret() {
            this.actionLoading = true;
            axios
                .get(DJANGO_API_URL + "delete_secret", {params: {
                    secret_id: this.secret_id,
                    csrftoken: this.csrftoken,
                },withCredentials: true,})
                .then((response) => {
                    this.actionLoading = false;
                    console.log(response);
                    if (response.data.message === "Unauthorized access") {
                        console.log("Unauthorized access");
                        window.location.href = "/login";
                    } else if (response.data.message === "Secret deleted successfully") {
                        this.showAlert = true;
                        this.alertContent = response.data.message;
                        this.alertType = "success"
                        this.getSecretsList();
                    } else {
                        this.showAlert = true;
                        this.alertContent = response.data.message;
                        this.alertType = "error"
                        this.getSecretsList();
                    }
                })
                .catch((error) => {
                    console.log(error);
                });
        },
        openModal(action, secretID) {
            this.modalOpen = true;
            this.action = action;
            this.secret_id = secretID;
            console.log(this.action, this.secret_id);
        },
        closeModal() {
            this.secretContent = '';
            this.showAlert = false;
            this.modalOpen = false;
        },
        getSecretsList() {
            axios
                .get(DJANGO_API_URL + "list_secrets", {withCredentials: true,})
                .then((response) => {
                    console.log(response);
                    if (response.data.message === "Unauthorized access") {
                        console.log("Unauthorized access");
                        window.location.href = "/login";
                    } else {
                        this.secrets = response.data;
                        this.isLoading = false;
                        console.log(this.secrets);
                    }
                })
                .catch((error) => {
                    console.log(error);
                });
        
        }
    },
    created() {
        this.getSecretsList();
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
                <v-card v-if="action=='Share' && secret_id!=''" >
                    <v-card-title>
                        Share the secret
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
                <v-card v-if="action=='Revoke' && secret_id!=''" >
                    <v-card-title>
                        Revoke a user's access to this secret
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
                <v-card v-if="action=='Display' && secret_id!=''" >
                    <v-card-title>
                        Display the secret
                    </v-card-title>
                    <v-card-text>
                        <v-textarea
                            v-model="secretContent"
                            label="Secret Content Will Be Loaded Here"
                            readonly
                        ></v-textarea>
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
                <v-card v-if="action=='Delete' && secret_id!=''" >
                    <v-card-title>
                        Delete the secret
                    </v-card-title>
                    <v-card-text>
                        Are you sure you want to delete this secret?
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
            <v-flex xs12 sm6 md6 lg1 style="height: 350px;" v-for="secret in secrets" :key="secret.SecretName">
                <v-card v-if="secrets.SharedWith != ''" style="height: 280px;width: 750px" variant="outlined" flat color="#aac7e8" class="yellow-card d-flex ma-7 pa-8 text-center d-block rounded-lg elevation-15 mx-auto">
                    <v-card-text class="flex-column d-flex align-center justify-center mt-4" color="light-blue lighten-4">
                        <div style="width: 45vh;overflow-y: auto;">
                            <div class="d-flex mb-2">
                                <div class="subheading mx-5"><v-icon left>mdi-book</v-icon><v-chip color="primary">Secret Name</v-chip></div>
                                <div class="text">{{ secret.SecretName }}</div>
                            </div>
                            <div class="d-flex my-2">
                                <div class="text mx-5"><v-icon left>mdi-calendar</v-icon><v-chip color="primary">Creation Date</v-chip></div>
                                <div class="text">{{ secret.DatetimeCreated }}</div>
                            </div>
                            <div class="d-flex mu-2">
                                <div class="text mx-5"><v-icon left>mdi-share</v-icon><v-chip color="primary">Share Status</v-chip></div>
                                <div class="text" v-if="(secret['SharedWith'].length === 0)">Private</div>
                                <div class="text" v-else>
                                    <p><strong><u>Shared with</u></strong></p><br>
                                    <div v-for="item in secret['SharedWith']" :key="item">{{ item.sharedWith }}</div>
                                </div>
                            </div>
                        </div>
                    </v-card-text>
                    <div class="flex-column">
                        <v-card-actions v-for="action in secretActions" :key="action">
                            <v-btn @click="openModal(action,secret.SecretID)" class="elevation-5 md-1 mx-3" style="width: 150px;" variant="outlined" flat color="primary">
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