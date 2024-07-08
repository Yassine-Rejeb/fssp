<script>
import { reactive, ref } from 'vue';
import { useRoute } from 'vue-router'
import axios from 'axios';

import store from '../store';

let DJANGO_API_URL = store.state.DJANGO_API_URL;

let secrets = reactive([{
    "SecretName": "",
    "DatetimeShared": "",
    "OwnerFullname": "",
    "OwnerUsername": "",
    "SecretID": "",
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
            secrets,
            thereAreSecrets: ref(false),
            modalOpen: false,
            action: '',
            secret_id: '',
            secretContent: ref(''),
            showAlert: false,
            alertContent: '',
            alertType: 'info',
            csrftoken: '',
            secretActions: ["Display", "Delete"],
            }
    },
    async mounted() {
        // this.listSharedSecrets();
        setInterval(() => {
            this.listSharedSecrets();
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
        async listSharedSecrets(){
            let resp = await axios
                .get(DJANGO_API_URL + "list_shared_secrets", {withCredentials: true,})
                .then((response) => {
                    // console.log("Let's check:",response);
                    if (response.data.message === "Unauthorized access") {
                        console.log("Unauthorized access");
                        window.location.href = "/login";
                    } else if (response.data.message === "Success" && response.data.secrets === []) {
                        this.isLoading = false;
                        this.thereAreSecrets = false;
                        console.log("No secrets found");
                    } else if (response.data.message === "Success" && response.data.secrets !== []) {
                        // Check if there is any change in the secrets
                        if (JSON.stringify(secrets) === JSON.stringify(response.data.secrets)) {
                            this.isLoading = false;
                        }else {
                            // Update the secrets
                            this.secrets = reactive([{
                                "SecretName": "",
                                "DatetimeShared": "",
                                "OwnerFullname": "",
                                "OwnerUsername": "",
                                "SecretID": "",
                            }]);

                            for (let key in response.data.secrets) {
                                this.secrets[key] = response.data.secrets[key];
}
                            this.isLoading = false;
                            if (this.secrets.length > 0 && this.secrets[0].SecretID !== "") {
                                this.thereAreSecrets = true;
                            }
                        }
                    }
                })
                .catch((error) => {
                    console.log(error);
                });
            return resp;
        },
        async displaySharedSecret() {
            this.actionLoading = true;
            let resp = await axios
                .get(DJANGO_API_URL + "display_shared_secret", {params: {
                    secret_id: this.secret_id,
                    csrftoken: this.csrftoken,
                }, withCredentials: true,})
                .then((response) => {
                    console.log(response);
                    if (response.data.message === "Secret Retrieved successfully") {
                        // console.log("Secret displayed successfully");
                        this.secretContent = response.data.secret_content;
                        this.showAlert = true;
                        this.alertContent = "Secret displayed successfully";
                        this.alertType = "success";
                        this.actionLoading = false;
                        this.listSharedSecrets();
                    } else if (response.data.message === "The share has expired") {
                        // console.log("The share has expired");
                        this.showAlert = true;
                        this.alertContent = "The share has expired";
                        this.alertType = "error";
                        this.actionLoading = false;
                        this.thereAreSecrets = false;
                        this.isLoading = true;
                        this.listSharedSecrets();
                    } else {
                        // console.log(response.data.message);
                        this.showAlert = true;
                        this.alertContent = response.data.message;
                        this.alertType = "error";
                        this.actionLoading = false;
                        this.listSharedSecrets();
                    }
                }).catch((error) => {
                    console.error(error);
                });
            return resp;
        },
        async removeAccessToSecret() {
            this.actionLoading = true;
            let resp = await axios
                .get(DJANGO_API_URL + "remove_access_to_secret", {params: {
                    secret_id: this.secret_id,
                    csrftoken: this.csrftoken,
                }, withCredentials: true,})
                .then((response) => {
                    console.log(response);
                    if (response.data.message === "Shared Secret removed successfully") {
                        this.showAlert = true;
                        this.alertContent = "Access removed successfully";
                        this.alertType = "success";
                        this.actionLoading = false;
                        this.isLoading = true;
                        this.thereAreSecrets = false;
                        this.listSharedSecrets();
                    } else {
                        this.showAlert = true;
                        this.alertContent = response.data.message;
                        this.alertType = "error";
                        this.actionLoading = false;
                        this.listSharedSecrets();
                    }
                }).catch((error) => {
                    console.error(error);
                });
            return resp;
        },
        openModal(action, secretID) {
            this.modalOpen = true;
            this.action = action;
            this.secret_id = secretID;
        },
        closeModal() {
            this.modalOpen = false;
            this.action = '';
            this.secret_id = '';
            this.secretContent = '';
            this.showAlert = false;
            this.alertContent = '';
            this.alertType = 'info';
            this.isLoading = true;
            this.listSharedSecrets();
        },
        async submit() {
            await this.getCsrfToken();
            if (this.action === 'Display') {
                this.displaySharedSecret();
            } else if (this.action === 'Delete') {
                this.removeAccessToSecret();
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
            <!-- V-Card for the Display functionality -->
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
    <v-container v-if="thereAreSecrets" >
        <v-layout v-if="!isLoading" wrap fluid style="overflow-y: auto;" class="flex-column">
            <v-flex xs12 sm6 md6 lg1 style="height: 350px;" 
            v-for="secret in secrets" :key="secret.SecretID" >
                <v-card style="height: 280px;width: 750px"
                variant="outlined" flat color="#aac7e8" class="yellow-card d-flex
                ma-7 pa-8 text-center d-block rounded-lg elevation-15 mx-auto">
                    <v-card-text class="flex-column d-flex align-center justify-center mt-4" color="light-blue lighten-4">
                        <div style="width: 45vh;overflow-y: auto;">
                            <div class="d-flex mb-2">
                            <div class="subtitle-1 mx-5"><v-icon left>mdi-book</v-icon><v-chip color="primary">Secret Name</v-chip></div>
                            <div class="text">{{ secret.SecretName }}</div>
                            </div>
                            <div class="d-flex my-2">
                            <div class="subtitle-2 mx-5"><v-icon left>mdi-account</v-icon><v-chip color="primary">Secret Owner</v-chip></div>
                            <div class="text">{{ secret.OwnerFullname }} ( <strong>Username:</strong> {{ secret.OwnerUsername }})</div>
                            </div>
                            <div class="d-flex mu-2">
                            <div class="subtitle-2 mx-5"><v-icon left>mdi-calendar</v-icon><v-chip color="primary">Share Date</v-chip></div>
                            <div class="text">{{ secret.DatetimeShared }}</div>
                            </div>
                        </div>
                    </v-card-text>
                    <div class="flex-column d-flex align-center justify-center">
                        <v-card-actions v-for="action in secretActions" :key="action">
                            <v-btn @click="openModal(action,secret.SecretID)" class="elevation-5 md-1 mx-3" style="width: 150px;" variant="outlined" flat color="primary">
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