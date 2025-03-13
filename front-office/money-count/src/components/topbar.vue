<template>
  <div class="top shadow-sm mt-0 p-5 bg-body position-absolute w">
    <div v-if="$route.path === '/'" style="display:flex; justify-content:flex-start;" class="">
        <img :src="image" class="img1"/> 
    </div>
    <div v-if="$route.path === '/'" style="display:flex; justify-content:flex-end;" class="">
      <btn_loginVue class="btn_login mx-2"/>
      <btn_signUpVue class="btn_signUP"/>
    </div>
    <div v-if="$route.path != '/' && $route.path != '/registry'">
      <Profil_PhotoVue class="profil"></Profil_PhotoVue>
    </div>
  </div>
</template>

<script>
  import Profil_PhotoVue from './Profil_Photo.vue';
  import btn_loginVue from './btn_login.vue';
  import btn_signUpVue from './btn_signUp.vue';
  export default {
    components: {Profil_PhotoVue, btn_loginVue, btn_signUpVue},
    props:{
      image:String,
    },
    
  }
</script>

<style>
body{
    overflow: hidden;
}

.img1 {
  position: absolute;
	width: 30px;
}

.w{
  width: 100% !important;
}
.p-5{
  padding: 3.3em !important;
}
.profil{
  position:absolute;
  left: 1150px;
  top:15px;
}
</style>