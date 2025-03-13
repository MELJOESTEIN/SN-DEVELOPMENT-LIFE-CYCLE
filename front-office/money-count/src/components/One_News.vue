<template>
    <div class="news-container mx-auto">
        <div v-if="this.cookie" v-for="(article, ind) in articles" :key="article.source.id" class="news-item">
            <div class="col bg-transparent rounded shadow" style="max-width:20vh ; max-height:20vh;" >
                    <img :src="article.urlToImage" alt="" class="img-fluid img-thumbnail" style="max-width: 100%; max-height: 100%;" @click="articleInfo(article.url)"  >
            </div>
        </div>

        <div v-if="!this.cookie" v-for="(articleA, index) in articlesAnom" :key="`article-${index}`" class="news-item">
            <div class="col bg-transparent rounded shadow" style="max-width:20vh ; max-height:20vh;" >
                    <img :src="articleA.urlToImage" alt="" class="img-fluid img-thumbnail" style="max-width: 100%; max-height: 100%;" @click="articleInfo(articleA.url)"  >
            </div>
        </div>
    </div>
</template>

<script>
import Cookies from 'js-cookie'
export default {
    components: { },
    data() {
        return {
        cookie : Cookies.get('session'),
        }
    },
    props :{
        articles: {
            type: Array,
            required: true
        },
        articlesAnom: {
            type: Array,
            required: true
        },
        // image : String
    },
    methods:{
        articleInfo(url) {
            // window.location.href=url
            window.open(url, '_blank', 'noreferrer');
        }
    }
}
</script>

<style>
.news-container {
    width: 100ch;
  display: flex;
  flex-direction: row;
  justify-content: center;
  overflow-x: scroll;
}

.news-item {
  flex: 0 0 auto;
  margin-right: 16px;
  cursor:pointer;
}
</style>