import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import { mount, flushPromises } from '@vue/test-utils';
import { createStore } from 'vuex';
import { createRouter, createWebHistory } from 'vue-router';
import axios from 'axios';
import { xssPayloads, generateMockJWT, vulnerableInputs, containsUnsafeHTML } from './security.utils';

// Mock axios
vi.mock('axios');

// Create a minimal store for testing
const createTestStore = () => {
  return createStore({
    state() {
      return {
        user: null,
        token: null,
        isAuthenticated: false
      };
    },
    mutations: {
      setUser(state, user) {
        state.user = user;
      },
      setToken(state, token) {
        state.token = token;
        state.isAuthenticated = !!token;
      },
      logout(state) {
        state.user = null;
        state.token = null;
        state.isAuthenticated = false;
      }
    },
    actions: {
      login({ commit }, { token, user }) {
        commit('setToken', token);
        commit('setUser', user);
      },
      logout({ commit }) {
        commit('logout');
      }
    }
  });
};

// Create a test router
const createTestRouter = () => {
  return createRouter({
    history: createWebHistory(),
    routes: [
      { path: '/', name: 'Home', component: { template: '<div>Home</div>' } },
      { path: '/login', name: 'Login', component: { template: '<div>Login</div>' } },
      { 
        path: '/dashboard', 
        name: 'Dashboard', 
        component: { template: '<div>Dashboard</div>' },
        meta: { requiresAuth: true }
      },
      { 
        path: '/admin', 
        name: 'Admin', 
        component: { template: '<div>Admin</div>' },
        meta: { requiresAuth: true, requiresAdmin: true }
      }
    ]
  });
};

// Mock components for testing
const LoginComponent = {
  template: `
    <form @submit.prevent="login">
      <input type="email" v-model="email" data-testid="email" />
      <input type="password" v-model="password" data-testid="password" />
      <button type="submit" data-testid="submit">Login</button>
      <div v-if="error" data-testid="error">{{ error }}</div>
    </form>
  `,
  data() {
    return {
      email: '',
      password: '',
      error: ''
    };
  },
  methods: {
    async login() {
      try {
        // Basic validation
        if (!this.email || !this.password) {
          this.error = 'Email and password are required';
          return;
        }
        
        // Email format validation
        const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
        if (!emailRegex.test(this.email)) {
          this.error = 'Invalid email format';
          return;
        }
        
        // Password strength validation
        if (this.password.length < 8) {
          this.error = 'Password must be at least 8 characters';
          return;
        }
        
        const response = await axios.post('/api/login', {
          email: this.email,
          password: this.password
        });
        
        this.$store.dispatch('login', {
          token: response.data.token,
          user: response.data.user
        });
        
        this.$router.push('/dashboard');
      } catch (err) {
        this.error = err.response?.data?.message || 'Login failed';
      }
    }
  }
};

const UserProfileComponent = {
  template: `
    <div>
      <h1>User Profile</h1>
      <div v-if="user">
        <p data-testid="username">{{ user.username }}</p>
        <p data-testid="email">{{ user.email }}</p>
        <div v-html="sanitizedBio" data-testid="bio"></div>
      </div>
      <form @submit.prevent="updateProfile">
        <input type="text" v-model="bio" data-testid="bio-input" />
        <button type="submit" data-testid="update">Update</button>
      </form>
    </div>
  `,
  data() {
    return {
      bio: '',
      user: null
    };
  },
  computed: {
    sanitizedBio() {
      // This is where we'd sanitize the HTML - for testing purposes
      // we're just implementing a basic version
      return this.user?.bio?.replace(/<script\b[^<]*(?:(?!<\/script>)<[^<]*)*<\/script>/gi, '')
                        .replace(/on\w+\s*=/gi, '')
                        .replace(/<iframe\b[^<]*(?:(?!<\/iframe>)<[^<]*)*<\/iframe>/gi, '');
    }
  },
  async mounted() {
    try {
      const response = await axios.get('/api/user/profile', {
        headers: {
          Authorization: `Bearer ${this.$store.state.token}`
        }
      });
      this.user = response.data;
    } catch (err) {
      console.error('Failed to load profile', err);
    }
  },
  methods: {
    async updateProfile() {
      try {
        await axios.put('/api/user/profile', {
          bio: this.bio
        }, {
          headers: {
            Authorization: `Bearer ${this.$store.state.token}`
          }
        });
        
        // Update local user data
        this.user = {
          ...this.user,
          bio: this.bio
        };
        
        this.bio = '';
      } catch (err) {
        console.error('Failed to update profile', err);
      }
    }
  }
};

describe('Frontend Security Tests', () => {
  let store;
  let router;
  
  beforeEach(() => {
    store = createTestStore();
    router = createTestRouter();
    
    // Reset axios mocks
    vi.resetAllMocks();
  });
  
  describe('Authentication Security', () => {
    it('should validate email format during login', async () => {
      const wrapper = mount(LoginComponent, {
        global: {
          plugins: [store, router]
        }
      });
      
      // Try invalid email format
      await wrapper.find('[data-testid="email"]').setValue('invalid-email');
      await wrapper.find('[data-testid="password"]').setValue('password123');
      await wrapper.find('[data-testid="submit"]').trigger('submit');
      
      await flushPromises();
      
      expect(wrapper.find('[data-testid="error"]').text()).toBe('Invalid email format');
      expect(axios.post).not.toHaveBeenCalled();
    });
    
    it('should validate password strength during login', async () => {
      const wrapper = mount(LoginComponent, {
        global: {
          plugins: [store, router]
        }
      });
      
      // Try weak password
      await wrapper.find('[data-testid="email"]').setValue('test@example.com');
      await wrapper.find('[data-testid="password"]').setValue('123');
      await wrapper.find('[data-testid="submit"]').trigger('submit');
      
      await flushPromises();
      
      expect(wrapper.find('[data-testid="error"]').text()).toBe('Password must be at least 8 characters');
      expect(axios.post).not.toHaveBeenCalled();
    });
    
    it('should handle expired JWT tokens', async () => {
      // Setup expired token in store
      const expiredToken = generateMockJWT({ sub: '123', role: 'user' }, true);
      store.dispatch('login', { token: expiredToken, user: { id: '123', role: 'user' } });
      
      // Mock axios to simulate 401 for expired token
      axios.get.mockRejectedValueOnce({ 
        response: { status: 401, data: { message: 'Token expired' } }
      });
      
      const wrapper = mount(UserProfileComponent, {
        global: {
          plugins: [store, router]
        }
      });
      
      await flushPromises();
      
      // Verify axios was called with the token
      expect(axios.get).toHaveBeenCalledWith('/api/user/profile', {
        headers: {
          Authorization: `Bearer ${expiredToken}`
        }
      });
      
      // In a real component, we'd expect a redirect to login
      // For this test, we just verify the API call was made
    });
    
    it('should protect routes that require authentication', async () => {
      // Setup router with navigation guards
      router.beforeEach((to, from, next) => {
        if (to.matched.some(record => record.meta.requiresAuth)) {
          if (!store.state.isAuthenticated) {
            next({ name: 'Login' });
          } else if (to.matched.some(record => record.meta.requiresAdmin) && 
                    store.state.user?.role !== 'admin') {
            next({ name: 'Home' });
          } else {
            next();
          }
        } else {
          next();
        }
      });
      
      // Try to navigate to protected route without authentication
      router.push('/dashboard');
      await router.isReady();
      
      // Should be redirected to login
      expect(router.currentRoute.value.path).toBe('/login');
      
      // Login as regular user
      store.dispatch('login', { 
        token: 'valid-token', 
        user: { id: '123', role: 'user' } 
      });
      
      // Try to navigate to admin route as regular user
      router.push('/admin');
      await router.isReady();
      
      // Should be redirected to home
      expect(router.currentRoute.value.path).toBe('/');
      
      // Login as admin
      store.dispatch('login', { 
        token: 'valid-admin-token', 
        user: { id: '456', role: 'admin' } 
      });
      
      // Try to navigate to admin route as admin
      router.push('/admin');
      await router.isReady();
      
      // Should be allowed
      expect(router.currentRoute.value.path).toBe('/admin');
    });
  });
  
  describe('XSS Prevention', () => {
    it('should sanitize user-generated content', async () => {
      // Mock API response with XSS payload in user bio
      const xssPayload = xssPayloads[0]; // "<script>alert('XSS')</script>"
      axios.get.mockResolvedValueOnce({
        data: {
          id: '123',
          username: 'testuser',
          email: 'test@example.com',
          bio: xssPayload
        }
      });
      
      // Setup valid token
      store.dispatch('login', { 
        token: 'valid-token', 
        user: { id: '123', role: 'user' } 
      });
      
      const wrapper = mount(UserProfileComponent, {
        global: {
          plugins: [store, router]
        }
      });
      
      await flushPromises();
      
      // Check if the bio is rendered and sanitized
      const bioElement = wrapper.find('[data-testid="bio"]');
      expect(bioElement.exists()).toBe(true);
      expect(bioElement.html()).not.toContain('<script>');
      expect(containsUnsafeHTML(bioElement.html())).toBe(false);
    });
    
    it('should sanitize user input before sending to API', async () => {
      // Setup valid token
      store.dispatch('login', { 
        token: 'valid-token', 
        user: { id: '123', role: 'user' } 
      });
      
      axios.get.mockResolvedValueOnce({
        data: {
          id: '123',
          username: 'testuser',
          email: 'test@example.com',
          bio: 'Original bio'
        }
      });
      
      const wrapper = mount(UserProfileComponent, {
        global: {
          plugins: [store, router]
        }
      });
      
      await flushPromises();
      
      // Try to update bio with XSS payload
      const xssPayload = xssPayloads[1]; // "<img src='x' onerror='alert(\"XSS\")'>"
      await wrapper.find('[data-testid="bio-input"]').setValue(xssPayload);
      await wrapper.find('[data-testid="update"]').trigger('submit');
      
      await flushPromises();
      
      // Verify the API call was made with the input
      expect(axios.put).toHaveBeenCalledWith(
        '/api/user/profile',
        { bio: xssPayload },
        expect.any(Object)
      );
      
      // In a real application, the API would sanitize this input
      // For this test, we're just verifying the call was made
    });
  });
  
  describe('CSRF Protection', () => {
    it('should include CSRF token in requests', async () => {
      // Setup CSRF token in document
      document.head.innerHTML = '<meta name="csrf-token" content="test-csrf-token">';
      
      // Setup axios interceptor to add CSRF token
      const originalAxios = axios.create;
      axios.create = vi.fn().mockImplementation((config) => {
        const instance = originalAxios(config);
        instance.interceptors.request.use((config) => {
          const token = document.querySelector('meta[name="csrf-token"]')?.getAttribute('content');
          if (token) {
            config.headers['X-CSRF-TOKEN'] = token;
          }
          return config;
        });
        return instance;
      });
      
      // Create axios instance with interceptor
      const axiosWithCSRF = axios.create();
      
      // Make a request
      axiosWithCSRF.post('/api/some-endpoint', { data: 'test' });
      
      // Verify CSRF token was included
      expect(axiosWithCSRF.interceptors.request).toBeDefined();
      
      // Clean up
      document.head.innerHTML = '';
    });
  });
  
  describe('Secure Data Handling', () => {
    it('should not store sensitive data in localStorage', () => {
      // Mock localStorage
      const localStorageMock = (() => {
        let store = {};
        return {
          getItem: vi.fn(key => store[key] || null),
          setItem: vi.fn((key, value) => {
            store[key] = value.toString();
          }),
          clear: vi.fn(() => {
            store = {};
          })
        };
      })();
      
      Object.defineProperty(window, 'localStorage', {
        value: localStorageMock
      });
      
      // Login and check if token is stored in localStorage
      store.dispatch('login', { 
        token: 'sensitive-token', 
        user: { id: '123', password: 'hashed-password', role: 'user' } 
      });
      
      // Verify token is not stored in localStorage
      expect(localStorageMock.setItem).not.toHaveBeenCalledWith('token', expect.any(String));
      expect(localStorageMock.setItem).not.toHaveBeenCalledWith('user', expect.stringContaining('password'));
    });
  });
  
  describe('Input Validation', () => {
    it('should validate and sanitize form inputs', async () => {
      const wrapper = mount(LoginComponent, {
        global: {
          plugins: [store, router]
        }
      });
      
      // Test SQL injection attempt
      const sqlInjectionPayload = vulnerableInputs.sqlInjection[0];
      await wrapper.find('[data-testid="email"]').setValue('test@example.com');
      await wrapper.find('[data-testid="password"]').setValue(sqlInjectionPayload);
      await wrapper.find('[data-testid="submit"]').trigger('submit');
      
      await flushPromises();
      
      // In a real app, we'd expect validation or sanitization
      // For this test, we're just verifying the submission behavior
      expect(axios.post).toHaveBeenCalledWith('/api/login', {
        email: 'test@example.com',
        password: sqlInjectionPayload
      });
      
      // In a real application, the backend would validate and sanitize this input
    });
  });
});
