<script>
import { useRoute } from 'vue-router'

let secrets = [
{"Title": "Private Key for Dev Instance", "Date": "16:46 28/05/2022", "Owner Full Name": "John F. Doe", "Owner Username": "XC4liber"},
{"Title": "Token for CI/CD Pipeline", "Date": "10:11 21/11/2022", "Owner Full Name": "John F. Doe", "Owner Username": "XC4liber"}
]
let secretActions = ["Display", "Delete"];

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
            secrets,
            secretActions
        }
    },
}
</script>

<template>
<!-- v-if="showSideBarSelected == 'Manage Secrets' && showBottomNavSelected == 'Shared with me'" -->
 <div class="container ml-10">
    <v-layout wrap fluid style="overflow-y: auto;" class="flex-column">
        <v-flex xs12 sm6 md6 lg1 style="height: 350px;" 
        v-for="secret in secrets" :key="secret.Title" >
    <v-card style="height: 280px;width: 800px"
            variant="outlined" flat color="#aac7e8" class="yellow-card d-flex
            ma-7 pa-8 text-center d-block rounded-lg elevation-15 mx-auto">
            <v-card-text class="flex-column d-flex align-center justify-center mt-4" color="light-blue lighten-4">
                <div style="width: 45vh;overflow-y: auto;">
                    <div class="d-flex mb-2">
                    <div class="subtitle-1 mx-5"><v-icon left>mdi-book</v-icon><v-chip color="primary">Title</v-chip></div>
                    <div class="text">{{ secret.Title }}</div>
                    </div>
                    <div class="d-flex my-2">
                    <div class="subtitle-2 mx-5"><v-icon left>mdi-account</v-icon><v-chip color="primary">Owner</v-chip></div>
                    <div class="text">{{ secret["Owner Full Name"] }} ({{ secret["Owner Username"] }})</div>
                    </div>
                    <div class="d-flex mu-2">
                    <div class="subtitle-2 mx-5"><v-icon left>mdi-calendar</v-icon><v-chip color="primary">Date</v-chip></div>
                    <div class="text">{{ secret.Date }}</div>
                    </div>
                </div>
                </v-card-text>
        <div class="flex-column d-flex align-center justify-center">
            <v-card-actions v-for="action in secretActions" :key="action">
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