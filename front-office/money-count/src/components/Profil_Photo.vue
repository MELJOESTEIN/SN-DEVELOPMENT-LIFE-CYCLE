<template>
  <div class="avatar-preview">
    <input
      type="file"
      accept="image/*"
      class="hidden"
      ref="file"
      @change="change"
    />
    <img :src="src||'https://www.web-soluces.net/webmaster/avatar/FacebookCom-Garcon.jpg'" class="avatar-preview" @click="browse()" />
  </div>
</template>
  
<script>
import image from "../assets/avatar.png"
export default {
  components: { image},
  data() {
    return {
      
    }
  },
  props: {
    value: File,
    defaultSrc: String,
  },
  watch: {
    value(file) {
      if (!file) {
        this.src = this.defaultSrc;
        this.$refs.file.value = "";
      } else {
        let reader = new FileReader();
        reader.readAsDataURL(file);
        reader.onload = (e) => {
          this.src = e.target.result;
        };
      }
    },
  },
  data() {
    return {
      src: this.defaultSrc,
    };
  },
  methods: {
    browse() {
      this.$refs.file.click();
    },
    remove() {
      this.$emit("input", null);
    },
    change(e) {
      let reader = new FileReader();
      reader.readAsDataURL(e.target.files[0]);
      reader.onload = (e) => {
        this.src = e.target.result;
        console.log(this.src)
      };
    },
  },
};
</script>

<style>
.avatar-preview {
  width: 48px;
  height: 48px;
  border-radius: 50%;
}

.hidden {
  display: none;
}

</style>
