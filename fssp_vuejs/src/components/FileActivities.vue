<template>
  <v-data-table :headers="headers" :items="items" class="elevation-1">
    <template #item="{ item }">
      <tr>
        <td>{{ item.name }}</td>
        <td>{{ item.age }}</td>
        <td>{{ item.city }}</td>
      </tr>
    </template>
  </v-data-table>
</template>

<script>
export default {
  data() {
    return {
      headers: [
        { text: 'Name', value: 'name' },
        { text: 'Age', value: 'age' },
        { text: 'City', value: 'city' },
      ],
      items: [
        { name: 'Alice', age:  30, city: 'New York' },
        { name: 'Bob', age:  25, city: 'Los Angeles' },
        { name: 'Charlie', age:  35, city: 'Chicago' },
      ],
    };
  },
};
</script>
