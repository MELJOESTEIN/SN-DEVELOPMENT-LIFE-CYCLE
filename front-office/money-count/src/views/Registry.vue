<template>
  <div>
  <topbar/>
  <div class="container-fluid d-flex flex-column justify-content-center align-items-center" style="width: 300px; height: 600px;">
    <div v-if="showRegistry" class="container-fluid d-flex flex-column justify-content-center align-items-center" style="width: 300px; height: 600px;">
      <h4 class="mb-4 d-flex align-items-center justify-content-center" style="font-size:20px !important; font-weight:bold;">Welcome to EpiCoin!</h4>
      <button class="btn btn-primary w-100 d-flex justify-content-center align-items-center"  type="button" @click="showRegistry = false"><span class="material-symbols-outlined p-2 text-dark">person</span>Sign up with email</button>

      <div class="my-2 text-secondary" style="width: 100%; height: 20px; border-bottom: 1px solid grey; font-weight: bold; text-align: center">
        <span class="position-absolute mt-2" style="font-size: 10px; background-color: white; ">
          or 
        </span>
    </div>
    <Oauth2/>
    <div class="d-flex align-items-center justify-content-center my-3" style="font-size:10px; color: gray;">Already registered?&nbsp; <a href="/login" class="underline underline-offset-2 "> Log In</a></div>    
    </div>
    <div v-else style="height:330px;">
      <span class="material-symbols-outlined back" style="position:absolute; " @click="back">arrow_back</span>
      <h2 class="d-flex align-items-center justify-content-center" style="font-size:20px !important; font-weight:bold;">Create an Account</h2>
      <form class="my-3">
        <div class="form-group my-3">
          <label for="nom">Nom :</label>
          <input class="form-control w-100" type="text" id="nom" v-model="formData.firstname" required>
        </div>
        <div class="form-group my-3">
          <label for="prenom">Prénom :</label>
          <input class="form-control w-100" type="text" id="prenom" v-model="formData.lastname" required>
        </div>
        <div class="form-group my-3">
          <label for="username">Username :</label>
          <input class="form-control w-100" type="text" id="username" v-model="formData.username" required>
        </div>
        <div class="form-group my-3">
          <label for="email">Email :</label>
          <input class="form-control w-100" type="email" id="email" v-model="formData.email" required>
        </div>
        <div class="form-group">
          <label for="password">Mot de passe :</label>
          <input class="form-control w-100" type="password" id="password" v-model="formData.password" required>
        </div>
        <div class="form-group">
          <label for="password_conf">Confirmer le mot de passe :</label>
          <input class="form-control w-100" type="password" id="password_conf" v-model="c_password" required>
        </div>
        <div class="form-group my-4">
          <input type="checkbox" required> <span style="font-size:10px; ">I have read and agree to EpiCoin's Terms of Service and Privacy Policy. </span> 
        </div>
        <div class="form-group ">
          <button class="btn btn-primary w-100" type="submit" @click.prevent="submitForm">Create an Account </button>
        </div>
      </form>
    </div>

    </div>
  </div>

</template>

<script>

import * as Vue from 'vue' // in Vue 3
import axios from 'axios'
import VueAxios from 'vue-axios'
import topbar from '../components/topbar.vue'
import Oauth2 from '../components/Oauth2.vue'
import Cookies from 'js-cookie'
export default {
  components: { topbar, Oauth2},
  data() {
    return {
      showRegistry: true,
      c_password:'',
      response:'',
      formData: {
        firstname:'',
        lastname:'',
        username:'',
        email:'',
        password:'',
        role:'',
      },
    }
  },
  methods :{
    back: function () {
      this.showRegistry = !this.showRegistry;
    },
    async submitForm() {
      if (this.formData.password == this.c_password){
        await axios({
            method: "post",
            url: 'http://localhost:4000/register',
            data: {
              firstname: this.formData.firstname,
              lastname: this.formData.lastname,
              username: this.formData.username,
              email: this.formData.email,
              password: this.formData.password,
              role:'user',
            }
        }).then(response => {
            this.response = response
            console.log(response)
            this.$swal('Registery', 'God registery','success', 'OK');
            this.$router.push({ name: "Login"})
        }).catch(e => {
            this.response = e.code
            this.$swal('Registry', 'Try again','error')
            router.push({name:"Registry"})
        })
        
      }else{
        this.$swal('Registry', 'Try again','error')
        router.push({name:"Registry"})
      }
            
    }
  }
}
</script>

<style scoped>
  .back {
    cursor: pointer;
  }
  .back:hover{
    color:blue;
  }
</style>