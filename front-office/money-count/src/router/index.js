import { createRouter, createWebHistory } from 'vue-router'
import Cookies from 'js-cookie'

const router = createRouter({
	history: createWebHistory(),
	routes: [
		// {
		// 	path: '/:pathMatch(.*)*',
		// 	name: "NotFound",
		// 	component: PageNotFound,
		// 	beforeEnter: (to, from, next) => {
		// 		if (Cookies.get('session')) {
		// 		next()
		// 		} else {
		// 		next('/login')
		// 		}
		// 	}
		// },
		{
			path: '/',
			component: () => import('@/views/Home.vue'),
			name: "Anonyme",
			beforeEnter: (to, from, next) => {
				if (!Cookies.get('session')) {
				  next()
				} else {
				  next('/home')
				}
			  }
			
		},
		{
			path: '/login',
			component: () => import('@/views/Login.vue'),
			name: "Login",
			beforeEnter: (to, from, next) => {
				if (!Cookies.get('session')) {
				  next()
				} else {
				  next('/home')
				}
			  }
		},
		{
			path: '/registry',
			component: () => import('@/views/Registry.vue'),
			name: "Registry",
		},
		{
			path: '/home',
			component: () => import('@/views/dashboard/dashboard.vue'),
			name: "Dashboard",
			// beforeEnter: (to, from, next) => {
			// 	if (Cookies.get('session')) {
			// 	  next()
			// 	} else {
			// 	  next('/login')
			// 	}
			//   },
			children: [
				{
					path: '/home',
					component: () => import('@/views/Home.vue'),
					name: "Home",
					beforeEnter: (to, from, next) => {
						if (Cookies.get('session')) {
						  next()
						} else {
						  next('/login')
						}
					  }
				},
				{
					path: '/articles',
					component: () => import('@/views/Articles.vue'),
					name: "Articles",
					beforeEnter: (to, from, next) => {
						if (Cookies.get('session')) {
						  next()
						} else {
						  next('/login')
						}
					  }
				},
				{
					path: "/cours",
					component: () => import('@/views/Cours.vue'),
					name: "Cours",
					beforeEnter: (to, from, next) => {
						if (Cookies.get('session')) {
						  next()
						} else {
						  next('/login')
						}
					  }
				},
				{
					path: "/profil",
					component: () => import('@/views/Profil.vue'),
					name: "Profil",
					beforeEnter: (to, from, next) => {
						if (Cookies.get('session')) {
						  next()
						} else {
						  next('/login')
						}
					  },
				}
			]
		},
		
		
	],
})

export default router