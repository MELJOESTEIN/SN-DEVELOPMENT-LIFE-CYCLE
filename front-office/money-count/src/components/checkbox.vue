<template>
    <div>
      <input class="color" type="checkbox" v-model="isChecked" v-on:change="handleChange" @change="checkIfInDatabase">
    </div>
</template>
  

<script>


export default {
  data() {
    return {
      isChecked: this.state
    }
  },
  props :{
    index : Number,
    value: String,
    state: Boolean,
  },
  methods: {
    handleChange() {
      console.log(this.checkIfInDatabase)
    }
  }
}
</script>
<style>
@keyframes example {
  0% {background-color: red;}
  25% {background-color: blue;}
  50% {background-color: yellow;}
  75% {background-color: green;}
  100% {background-color: red;}
}
.color{
  transform: scale(1.3);
  width: 15px;
  height: 20px;
  border-radius: 50% !important;
  border: none;
  /* transition: color 0.5s ease; */
  /* animation: example 2s linear infinite; */
}


</style>