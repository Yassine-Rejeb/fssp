<script>
import { useRoute } from 'vue-router';
import store from '../store';

let files = [
    {"Title": "Key for Dev Instance","Filename": "Dev-Instance.pem", "Date": "16:46 28/05/2022", "Size": "401 KB", "Share Status": ["John_Doe16", "Jane02", "JannahXYZ"]},
    {"Title": "Key for Dev Instance","Filename": "Dev-Instance.pem", "Date": "16:46 28/05/2022", "Size": "401 KB", "Share Status": ["John_Doe16", "Jane02", "JannahXYZ"]},
    {"Title": "Key for Dev Instance","Filename": "Dev-Instance.pem", "Date": "16:46 28/05/2022", "Size": "401 KB", "Share Status": ["John_Doe16", "Jane02", "JannahXYZ"]},
    {"Title": "Key for Dev Instance","Filename": "Dev-Instance.pem", "Date": "16:46 28/05/2022", "Size": "401 KB", "Share Status": ["John_Doe16", "Jane02", "JannahXYZ"]},
    {"Title": "Key for Dev Instance","Filename": "Dev-Instance.pem", "Date": "16:46 28/05/2022", "Size": "401 KB", "Share Status": ["John_Doe16", "Jane02", "JannahXYZ"]},
    {"Title": "Token for CI/CD Pipeline","Filename": "JWT.txt", "Date": "10:11 21/11/2022", "Size": "16 KB", "Share Status": []}
    ]

let fileActions = ["Share", "Revoke", "Download", "Delete"];

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
            files,
            fileActions,
        }
    },
}
</script>

<template>
 <div class="container ml-10">
    <v-layout wrap fluid style="overflow-y: auto;" class="flex-column">
        <v-flex xs12 sm6 md6 lg1 style="height: 350px;bg-olor: '#333333';" 
        v-for="file in files" :key="file.Filename" >
    <v-card style="height: 280px;width: 700px;" 
            variant="outlined" flat color="#aac7e8" class="yellow-card d-flex yellow-card
            ma-7 pa-8 text-center d-block rounded-lg elevation-15 mx-auto">
        <v-card-text class="flex-column d-flex align-center justify-center mt-4" color="light-blue lighten-4">
            <div style="width: 45vh;overflow-y: auto;">
                <div class="d-flex mb-2">
                <div class="subheading mx-5"><v-icon left>mdi-file</v-icon><v-chip color="primary">Filename</v-chip></div>
                <div class="text">{{ file.Filename }}</div>
                </div>
                <div class="d-flex my-2">
                <div class="text mx-5"><v-icon left>mdi-calendar</v-icon><v-chip color="primary">Date</v-chip></div>
                <div class="text">{{ file.Date }}</div>
                </div>
                <div class="d-flex my-2">
                <div class="subheading mx-5"><v-icon left>mdi-database</v-icon><v-chip color="primary">Size</v-chip></div>
                <div class="text">{{ file.Size }}</div>
                </div>
                <div class="d-flex mu-2">
                <div class="text mx-5"><v-icon left>mdi-share</v-icon><v-chip color="primary">Share Status</v-chip></div>
                <div class="text" v-if="file['Share Status'].length === 0">Private</div>
                <div class="text" v-else>
                    <p class="text-decoration-underline font-weight-bold">Shared with</p><br>
                    <div v-for="item in file['Share Status']" :key="item">{{ item }}</div>
                </div>
                </div>
            </div>
            </v-card-text>
        <div class="flex-column">
            <v-card-actions v-for="action in fileActions" :key="action">
                <v-btn class="elevation-5 md-1" style="width: 150px;" variant="outlined" flat color="primary">
                    <span>{{ action }}</span>
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