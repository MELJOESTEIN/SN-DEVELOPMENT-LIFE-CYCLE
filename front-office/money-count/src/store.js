import Vue from 'vue'
import Vuex from 'vuex'

Vue.use(Vuex)

export default new Vuex.Store({
  state: {
    globalVar: "ma variable globale"
  },
  mutations: {
    updateGlobalVar(state, newValue) {
      state.globalVar = newValue
    }
  },
  actions: {
    setGlobalVar({ commit }, newValue) {
      commit('updateGlobalVar', newValue)
    }
  }
})
