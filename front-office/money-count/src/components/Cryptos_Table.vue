<script>
import OneCrypto from "./One_Crypto.vue";

export default {
  components: {
    "one-crypto": OneCrypto,
  },
  data() {
    return {
      titles: ["#", "Name", "Price", "24H Change", "24H Volume", "Favoris"],
      cryptoCurrenciesList: [],
      arrayLength: 100,
      cryptoCurrenciesShowned: [],
      favoritesCryptos: [],
      isVisible: false,
    };
  },
  async mounted() {
    const res = await fetch(
      "https://api.coingecko.com/api/v3/coins/markets?vs_currency=eur&order=market_cap_desc&per_page=100&page=1&sparkline=false"
    );
    const data = await res.json();
    // console.log(data);
    this.cryptoCurrenciesList = data;
    this.cryptoCurrenciesShowned = this.cryptoCurrenciesList;
  },
  watch: {
    arrayLength: function (value) {
      this.cryptoCurrenciesShowned = this.cryptoCurrenciesList.slice(0, value);
    },
  },
  methods: {
    updateFavorites: function (status, id) {
      if (status) {
        const cryptoToFavourite = this.cryptoCurrenciesShowned.find(
          (crypto) => {
            return crypto.id === id;
          }
        );
        cryptoToFavourite.isIncluded = true;
        console.log("Crypto to favorite");
        console.log(cryptoToFavourite);
        if (!this.favoritesCryptos.includes(cryptoToFavourite)) {
          this.favoritesCryptos.push(cryptoToFavourite);
        }
      } else {
        const cryptoToFavourite = this.cryptoCurrenciesShowned.find(
          (crypto) => {
            return crypto.id === id;
          }
        );
        cryptoToFavourite.isIncluded = false;
        const index = this.favoritesCryptos.indexOf(cryptoToFavourite);
        this.favoritesCryptos.splice(index, 1);
      }
      console.log("favorites Crypto tableau: ");
      console.log(this.favoritesCryptos);
    },
    toggleFavourite: function () {
      this.isVisible = !this.isVisible;
    },
  },
};
</script>

<template>
  <div>
    <div class="aligne">
      <div>
        <label for="" style="margin-right: 10px"
          >Nbr Crypto</label
        >
        <input type="number" min="10" max="100" v-model="arrayLength" />
      </div>
      <div>
        <button
          type="button"
          class="btn btn-outline-primary"
          @click="toggleFavourite"
        >
          Show {{ isVisible ? "All" : "Favourites" }}
        </button>
      </div>
    </div>
    <div class="container">
      <table class="table table-white">
        <thead>
          <tr>
            <th v-for="title in titles" :key="title">{{ title }}</th>
          </tr>
        </thead>
        <tbody v-if="!isVisible">
          <one-crypto
            v-for="(coin, index) in cryptoCurrenciesShowned"
            :key="coin.id"
            :coin="coin"
            :index="index"
            @set-favorite="updateFavorites"
          >
          </one-crypto>
        </tbody>
        <tbody v-else>
          <one-crypto
            v-for="(coin, index) in favoritesCryptos"
            :key="coin.id"
            :coin="coin"
            :index="index"
            @set-favorite="updateFavorites"
          >
          </one-crypto>
        </tbody>
      </table>
    </div>
  </div>
</template>

<style scoped>
.container {
  overflow: scroll;
  height: 60vh;
}
.aligne {
  display: flex;
  justify-content: space-between;
  margin: 6vh 0;
}

thead {
  position: sticky;
  top: 0;
  background-color: white;
}

/* #################################################### */
</style>
