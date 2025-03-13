<template>
	<aside class="shadow bg-body">
		<div class="first bg-body shadow-sm p-3">
			<div class="logo ">
				<img :src="logoURL" alt="Vue" /> 
			</div>
		</div>

		<div class="menu">
			<router-link :to="{name:'Home'}" class="button">
				<span class="material-icons">home</span>
				<span class="text">Home</span>
			</router-link>
			<router-link :to="{name:'Cours'}" class="button">
				<span class="material-icons">ssid_chart</span>
				<span class="text">Cours</span>
			</router-link>
			<router-link :to="{name:'Articles'}" class="button">
				<span class="material-icons">article</span>
				<span class="text">Articles</span>
			</router-link>
			<router-link :to="{name:'Profil'}" class="button">
				<span class="material-icons">face</span>
				<span class="text">Profil</span>
			</router-link>
		</div>

		<!-- <div class="flex"></div> -->
	</aside>
</template>

<script setup>
import { ref } from 'vue'
import logoURL from '../assets/logo.png'

</script>

<style lang="scss" scoped>
.first{
	width: 109%;
	margin-left: -7px;
}
aside {
	display: flex;
	flex-direction: column;

	background-color: var(--dark);
	color: var(--light);
	width: var(--sidebar-width);
	// width: calc(2rem + 32px);
	overflow: hidden;
	min-height: 100vh;
	padding: 1rem;

	transition: 0.2s ease-in-out;

	.flex {
		flex: 1 1 0%;
	}

	.logo {
		margin-bottom: 1rem;
		margin-left: 40%;

		img {
			width: 3rem;
		}
	}

	h3, .button .text {
		padding: 10%;
		opacity: 100%;
		transition: opacity 0.3s ease-in-out;
	}

	h3 {
		color: var(--grey);
		font-size: 0.875rem;
		margin-bottom: 0.5rem;
		text-transform: uppercase;
	}

	.menu {
		margin: 10 -1rem;

		.button {
			display: flex;
			align-items: center;
			text-decoration: none;

			transition: 0.2s ease-in-out;
			padding: 0.5rem 1rem;

			.material-icons {
				font-size: 2rem;
				color: var(--dark-atl);
				transition: 0.2s ease-in-out;
			}
			.text {
				color: var(--dark-alt);
				transition: 0.2s ease-in-out;
			}

			&:hover {
				background-color: var(--grey);

				.material-icons, .text {
					color: var(--light);
				}
			}

			&.router-link-exact-active {
				background-color: var(--dark-all);
				border-left: 5px solid var(--primary);

				.material-icons, .text {
					color: var(--light);
				}
			}
		}
	}

	.footer {
		opacity: 0;
		transition: opacity 0.3s ease-in-out;

		p {
			font-size: 0.875rem;
			color: var(--grey);
		}
	}

	@media (max-width: 1024px) {
		position: absolute;
		z-index: 99;
	}
}
</style>