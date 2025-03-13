<script>
export default {
  props: {
    coin: {
      required: true,
      type: Object,
    },
    index: {
      required: true,
      type: Number,
    },
  },
  methods: {
    toggleFavoriteStatus: function () {
      this.isFavorite = !this.isFavorite;
      // console.log(this.isFavorite);
    },
  },
  computed: {
    starStyle: function () {
      return {
        textAlign: "center",
        width: 100 + "%",
        color: this.isFavorite ? "blue" : "gray",
        cursor: "pointer",
      };
    },
  },
  data: function () {
    return {
      isFavorite: this.coin.isIncluded,
    };
  },
  watch: {
    isFavorite: function (value) {
      // console.log(value, this.coin.id);
      this.$emit("set-favorite", this.isFavorite, this.coin.id);
    },
  },
  emits: ["set-favorite"],
};
</script>

<template>
  <tr>
    <td class="text-muted">{{ index + 1 }}</td>
    <td>
      <img :src="coin.image" style="width: 2rem" class="me-3" />
      <span>
        {{ coin.name }}
      </span>
      <span class="ms-3 text-uppercase text-muted">
        {{ coin.symbol }}
      </span>
    </td>
    <td>${{ coin.current_price }}</td>
    <td
      :class="[
        coin.price_change_percentage_24h > 0 ? 'text-success' : 'text-danger',
      ]"
    >
      {{ coin.price_change_percentage_24h > 0 ? "+" : ""
      }}{{ coin.price_change_percentage_24h }} %
    </td>
    <td>${{ coin.total_volume.toLocaleString() }}</td>
    <td>
      <span
        class="material-icons"
        :style="starStyle"
        @click="toggleFavoriteStatus"
      >
        star
      </span>
    </td>
  </tr>
</template>
