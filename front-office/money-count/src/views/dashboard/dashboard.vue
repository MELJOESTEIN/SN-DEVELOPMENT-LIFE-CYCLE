<template>
	<div class="app container-fluid">
		<topbar class="top"/>
		<Sidebar />
		<router-view />
	</div>
</template>

<script setup>
import topbar from '../../components/topbar.vue'
import Sidebar from '../../components/Sidebar.vue'
</script>

<style lang="scss">
.top{
    left: 17.5em;    
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
	--sidebar-width: 200px;
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
	background: var(--light);
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

	main {
		margin-top: 7em;
		flex: 1 1 0;
		padding: 2rem;
		@media not all and (min-width: 1027px){
			position: relative;
			padding-left: 20rem;
		}
	}
}
</style>