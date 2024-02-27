<template>
  <div class="files-page">
    <AddFile v-if="isAddingFile" @close="isAddingFile = false" />
    <!-- rest of your page content here -->
  </div>
</template>

<script>
import AddFile from './NewFile.vue';

export default {
  components: {
    AddFile
  },
  data() {
    return {
      isAddingFile: false
    };
  },
  methods: {
    addFile() {
      this.isAddingFile = true;
    }
  }
};
</script>

<style scoped>
.files-page {
  position: relative;
}

.AddFile {
  position: absolute;
  top: 0;
  left: 0;
  z-index: 1000;
  transition: transform 0.3s ease;
  transform: scale(0);
}

.AddFile:hover {
  transform: scale(1);
}
</style>