<script>
import axios from 'axios';
import { ref, reactive } from 'vue';
import store from '../store';

let DJANGO_API_URL = store.state.DJANGO_API_URL;

export default {
    data() {
        return {
            isLoading: ref(true),
            data: reactive([{
                id: '', user: 'USERNAME', operation: 'OPERATION', object_type: 'OBJECT TYPE', object_name: 'OBJECT NAME', date: '1970-01-01 00:00:00'}
                ]),
            search: '',
            csrftoken: '',
        };
    },
    computed: {
        filteredItems() {
            return this.data.filter(item =>
            Object.values(item).some(val => 
                typeof val === 'string' && val.toLowerCase().includes(this.search.toLowerCase())
            )
        );
    }
    },
    methods: {
        async getCSRFToken() {
            let resp = axios
                .get(DJANGO_API_URL + "get_csrf_token", {withCredentials: true,})
                .then((response) => {
                    // console.log(response);
                    return response.data.csrftoken;
                })
                .catch((error) => {
                    console.log(error);
                });
            return resp;
        },
        async markAsRead(id) {
            let resp = await axios.get(DJANGO_API_URL + 'mark_notification_as_viewed', 
            {withCredentials: true, params: 
                {
                    csrfToken: this.csrftoken,
                    id: id,
                }})
            .then(response => {
                // console.log(response);
                if (response.data.message === 'Success') {
                    console.log('Marked as read');
                    this.updateNotifications();
                }
                else {
                    console.log(response.data.message);
                }
            }).catch(error => {
                console.log(error);
            });
            return resp;
        },
        async updateNotifications() {
            await axios.get(DJANGO_API_URL + 'get_notifications', 
            {withCredentials: true}).then(response => {
                // console.log(response);
                if (response.data.message === 'Success') {
                    this.data = response.data.data;
                    this.isLoading = false;
                }
                else {
                    // console.log(response.data.message);
                }
            }).catch(error => {
                console.log(error);
            });
        },
        searchItems() {
        // No action needed here as the computed property handles filtering
        }
  },
    async mounted() {
        this.csrftoken = await this.getCSRFToken();
        await axios.get(DJANGO_API_URL + 'get_notifications', 
        {withCredentials: true}).then(response => {
            // console.log(response);
            if (response.data.message === 'Success') {
                this.data = response.data.data;
                // console.log(this.data);
                this.isLoading = false;
                // this.updateNotifications();
            }
            else {
                // console.log(response.data.message);
            }
        }).catch(error => {
            console.log(error);
        });
  }
};
</script>

<template>
  <div>
    <v-text-field class="md-5 mt-5 elevation-2" v-model="search" label="Search" @input="searchItems" />
    <v-overlay :model-value="isLoading" class="align-center justify-center">
        <v-progress-circular
            v-if="isLoading"
            indeterminate
            color="primary"
        ></v-progress-circular>
      </v-overlay>
    <v-data-table v-if="!isLoading" :items="filteredItems" class="elevation-1">
      
      <template #item="{ item }">
        <tr>
          <td>{{ item.id }}</td>
          <td>{{ item.user }}</td>
          <td>{{ item.operation }}</td>
          <td>{{ item.object_type }}</td>
          <td>{{ item.object_name }}</td>
          <td>{{ item.date }}</td>
          <td style="" >
            <v-btn color="primary" @click="markAsRead(item.id)" style="float: right">
              <v-icon>mdi-eye</v-icon></v-btn>
          </td>
        </tr>
      </template>
    </v-data-table>
  </div>
</template>

