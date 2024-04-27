<script>
import axios from 'axios';
import { ref } from 'vue';

import store from '../store';

let DJANGO_API_URL = store.state.DJANGO_API_URL;

export default {
  data() {
    return {
      isLoading: ref(true),
      items: ref([
        { username: 'USERNAME', fullname: "FULL NAME" , operation: 'OPERATION', secret: 'SECRET NAME', date: '1970-01-01 00:00:00'},
        ]),
      search: '',
    };
  },
  computed: {
    filteredItems() {
      return this.items.filter(item =>
        Object.values(item).some(val => val.toLowerCase().includes(this.search.toLowerCase()))
      );
    }
  },
  methods: {
    searchItems() {
      // No action needed here as the computed property handles filtering
    }
  },
  async mounted() {
        await axios.get(DJANGO_API_URL + 'get_user_eventlogs', 
        {withCredentials: true}).then(response => {
            if (response.data.message === 'Success') {
                this.items = response.data.data;
                // console.log(this.items);
                this.isLoading = false;
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
          <td>{{ item.username }}</td>
          <td>{{ item.fullname }}</td>
          <td>{{ item.operation }}</td>
          <td>{{ item.secret }}</td>
          <td>{{ item.date }}</td>
        </tr>
      </template>
    </v-data-table>
  </div>
</template>

