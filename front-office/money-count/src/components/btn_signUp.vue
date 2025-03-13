<template>
  <div class="form-group">
    <button class="btn btn-primary btn-sm" @click="redirect">Sign UP</button>
  </div>
  </template>
  
  <script>
  export default {
    methods: {
      redirect() {
        this.$router.push({ name: "Registry"})
      }
    }
  }
  </script>