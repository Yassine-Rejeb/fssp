<template>
  <v-data-table :headers="headers" :items="items" class="elevation-1">
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
</template>

<script>
export default {
    data() {
        return {
            headers: [
                { text: 'Username', value: 'username' },
                { text: 'Full Name', value: 'fullname' },
                { text: 'Operation', value: 'operation' },
                { text: 'Secret', value: 'secret' },
                { text: 'Date & Time Of Operation', value: 'date'},

            ],
            items: [
                { username: 'Alice123', fullname: "Alice Cooper" , operation: 'Shared with you a secret', secret: 'Secret A', date: '2021-09-01 12:00:00'},
                { username: 'Bob', fullname: "Bob Smith", operation: 'Shared with you a secret', secret: 'Secret B', date: '2021-09-01 14:45:56'},
                { username: 'David', fullname: "David O'Conner", operation: 'Revoked your access to his secret', secret: 'Secret D', date: '2021-09-01 15:00:00'},
                { username: 'YOU', fullname: "YOU", operation: 'Created new secret', secret: 'Secret E', date: '2021-09-01 15:30:00'},
                { username: 'YOU', fullname: "YOU", operation: 'Shared a secret with CharlieOxO', secret: 'Secret E', date: '2021-09-01 15:45:00'}, 
                { username: 'Charlie', fullname: "Charlie Brown", operation: 'Displayed a secret you shared with him', secret: 'Secret F', date: '2021-09-01 16:00:00'},
            ],
        };
    },
};
</script>
