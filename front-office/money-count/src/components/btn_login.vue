<template>
  <div class="form-group">
    <button class="btn btn-light btn-sm" @click="redirect">Login</button>
  </div>
  </template>
  
  <script>
  export default {
    methods: {
      redirect() {
        this.$router.push({ name: "Login"})
      }
    }
  }
  </script>