<script>
import { useRoute } from 'vue-router'

let secrets = [
{"Title": "Private Key for Dev Instance", "Date": "16:46 28/05/2022", "Share Status": ["John_Doe16", "Jane02", "JannahXYZ", "Jane02", "JannahXYZ", "Jane02", "JannahXYZ", "Jane02", "JannahXYZ"]},
{"Title": "Token for CI/CD Pipeline", "Date": "10:11 21/11/2022", "Share Status": []}
]
let secretActions = ["Share", "Revoke", "Display", "Delete"];

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
    <div class="container ml-10">
        <v-layout wrap fluid style="overflow-y: auto;" class="flex-column">
            <v-flex xs12 sm6 md6 lg1 style="height: 350px;" v-for="secret in secrets" :key="secret.Title">
                <v-card style="height: 280px;width: 700px" variant="outlined" flat color="#aac7e8" class="yellow-card d-flex ma-7 pa-8 text-center d-block rounded-lg elevation-15 mx-auto">
                    <v-card-text class="flex-column d-flex align-center justify-center mt-4" color="light-blue lighten-4">
                        <div style="width: 45vh;overflow-y: auto;">
                            <div class="d-flex mb-2">
                                <div class="subheading mx-5"><v-icon left>mdi-book</v-icon><v-chip color="primary">Title</v-chip></div>
                                <div class="text">{{ secret.Title }}</div>
                            </div>
                            <div class="d-flex my-2">
                                <div class="text mx-5"><v-icon left>mdi-calendar</v-icon><v-chip color="primary">Date</v-chip></div>
                                <div class="text">{{ secret.Date }}</div>
                            </div>
                            <div class="d-flex mu-2">
                                <div class="text mx-5"><v-icon left>mdi-share</v-icon><v-chip color="primary">Share Status</v-chip></div>
                                <div class="text" v-if="secret['Share Status'].length === 0">Private</div>
                                <!-- I need the next sentence in the paragraph to be underlined + bold is there any vuetify classes for that -->
                                <div class="text" v-else>
                                    <p><strong><u>Shared with</u></strong></p><br>
                                    <div v-for="item in secret['Share Status']" :key="item">{{ item }}</div>
                                </div>
                            </div>
                        </div>
                    </v-card-text>
                    <div class="flex-column">
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