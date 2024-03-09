<script>

// Rules for the file name and file input
const rules = {
  required: (value) => !!value || 'Required.',
  filename: (value) => { 
    const pattern = /^[a-zA-Z0-9-_]+$/;
    return pattern.test(value) || 'Invalid filename.';
  },
  filename_size: (value) => {
    return value.length <= 50 || 'Filename must be less than 50 characters.';
  },
};

export default {
  data() {
    return {
      fileName: '',
      rules,
    };
  },
  methods: {
    createFile() {
      // Add logic to create the file and handle sharing
      console.log('Creating file:', this.fileName);
    },
  },
};
</script>

<template>
  <v-card style="height: 320px;width: 900px;" class="ma-7 pa-8 text-center d-block rounded-lg elevation-15 mx-auto" >
    <v-card-title>Create New File</v-card-title>
    <v-card-text>
      <v-form @submit.prevent="createFile">
        <v-text-field v-model="fileName" label="Filename" :rules="[rules.required, rules.filename, rules.filename_size]" ></v-text-field>
        <v-file-input label="File" multiple :rules="[rules.required]" ></v-file-input>
        <v-btn type="submit" color="primary">Create File</v-btn>
      </v-form>
    </v-card-text>
  </v-card>
</template>
