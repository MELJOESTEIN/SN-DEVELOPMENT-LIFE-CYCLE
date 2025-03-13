<script>
import { RouterView } from "vue-router";
</script>

<template>
	<div id="app container-fluid">
  		<RouterView />
	</div>
</template>

<style scoped>
#app {
	font-family: 'Montserrat', "Open Sans", Helvetica, Arial, sans-serif; font-size: 12px;
}
:root {
	--primary: #4ade80;
	--primary-alt: #22c55e;
	--grey: #64748b;
	--dark: #1e293b;
	--dark-alt: #334155;
	--dark-atl:#404347;
	--dark-all: #7698ff;
	--light: #f1f5f9;
	--red: #d4481d;
}
* {
	margin: 0;
	padding: 0;
	box-sizing: border-box;
	font-family: 'Montserrat', "Open Sans", Helvetica, Arial, sans-serif; font-size: 12px;
}

body {
	width: 100%;
	background: white;
}

button {
	cursor: pointer;
	appearance: none;
	border: none;
	outline: none;
	background: none;
}

.app {
	display: flex;
}
</style>
