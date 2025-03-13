<template>
  <div class="container-fluid shadow">
      <div class="dimention row" >
        <div class="col bg-transparent" style="max-width: 22%; max-height: 100%;">
            <img :src="image" alt="" class="img-fluid img-thumbnail" style="max-width: 100%; max-height: 100%;" >
        </div>
        <div class="texte col">
          <div class="shortname m-2" style="color:var(--red) !important;">
            {{thematic}}
          </div>
          <div class="title fs-4 m-2">
            {{title}}
          </div>
          <div class="date m-2">
            {{date}}
          </div>
          <div class="resume m-2">
            {{resumer}}     
          </div>
        </div>
    </div>
  </div>
</template>

<script>
export default {
  props: {
    thematic: String,
    title: String,
    date : Date,
    resumer: String,
    image: String,
  }
}
</script>

<style lang="scss">
*{
  text-align: justify;
  text-justify: inter-word;
}
.resumer{
  font-weight: 100;
	font-family: Montserrat, "Open Sans", Helvetica, Arial, sans-serif;
}
  @media screen and (max-width : 1064px) {
   
  }
</style>