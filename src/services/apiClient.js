/**
 * API Client for MT5 Trading Platform
 * Handles all API calls to the backend server
 */

const API_BASE_URL = 'http://localhost:5000/api';

class ApiClient {
  /**
   * Make an HTTP request to the API
   * @param {string} endpoint - API endpoint
   * @param {Object} options - Request options
   * @returns {Promise<any>} - Response data
   */
  async request(endpoint, options = {}) {
    const url = `${API_BASE_URL}${endpoint}`;
    const sessionId = localStorage.getItem('session_id');
    
    const config = {
      headers: {
        'Content-Type': 'application/json',
        ...(sessionId && { 'Authorization': `Bearer ${sessionId}` }),
        ...options.headers,
      },
      ...options,
    };

    if (config.body && typeof config.body === 'object') {
      config.body = JSON.stringify(config.body);
    }

    try {
      const response = await fetch(url, config);
      const data = await response.json();

      if (!response.ok) {
        throw new Error(data.error || 'Request failed');
      }

      return data;
    } catch (error) {
      console.error(`API Error (${endpoint}):`, error);
      throw error;
    }
  }

  // ===== Authentication =====

  /**
   * Login with username and password
   * @param {Object} credentials - User credentials
   * @returns {Promise<Object>} - User data and session ID
   */
  async login(credentials) {
    const response = await this.request('/auth/login', {
      method: 'POST',
      body: credentials,
    });
    if (response.session_id) {
      localStorage.setItem('session_id', response.session_id);
    }
    return response;
  }

  /**
   * Register a new user
   * @param {Object} userData - User registration data
   * @returns {Promise<Object>} - New user data and session ID
   */
  async register(userData) {
    const response = await this.request('/auth/register', {
      method: 'POST',
      body: userData,
    });
    if (response.session_id) {
      localStorage.setItem('session_id', response.session_id);
    }
    return response;
  }

  /**
   * Logout the current user
   * @returns {Promise<Object>} - Logout response
   */
  async logout() {
    try {
      await this.request('/auth/logout', { method: 'POST' });
    } finally {
      localStorage.removeItem('session_id');
    }
  }

  /**
   * Verify the current session
   * @returns {Promise<Object>} - User data if session is valid
   */
  async verifySession() {
    return await this.request('/auth/verify');
  }

  // ===== Account Management =====

  /**
   * Get all trading accounts
   * @returns {Promise<Array>} - List of trading accounts
   */
  async getAccounts() {
    return await this.request('/accounts');
  }

  /**
   * Create a new trading account
   * @param {Object} accountData - Trading account data
   * @returns {Promise<Object>} - New account data
   */
  async createAccount(accountData) {
    return await this.request('/accounts', {
      method: 'POST',
      body: accountData,
    });
  }

  /**
   * Update an existing trading account
   * @param {string} accountId - Account ID to update
   * @param {Object} accountData - Updated account data
   * @returns {Promise<Object>} - Updated account data
   */
  async updateAccount(accountId, accountData) {
    return await this.request(`/accounts/${accountId}`, {
      method: 'PUT',
      body: accountData,
    });
  }

  /**
   * Delete a trading account
   * @param {string} accountId - Account ID to delete
   * @returns {Promise<Object>} - Deletion response
   */
  async deleteAccount(accountId) {
    return await this.request(`/accounts/${accountId}`, {
      method: 'DELETE',
    });
  }

  // ===== User Management =====

  /**
   * Get all platform users (admin only)
   * @returns {Promise<Array>} - List of users
   */
  async getUsers() {
    return await this.request('/users');
  }

  /**
   * Create a new platform user (admin only)
   * @param {Object} userData - User data
   * @returns {Promise<Object>} - New user data
   */
  async createUser(userData) {
    return await this.request('/users', {
      method: 'POST',
      body: userData,
    });
  }

  /**
   * Update an existing user (admin only)
   * @param {string} userId - User ID to update
   * @param {Object} userData - Updated user data
   * @returns {Promise<Object>} - Updated user data
   */
  async updateUser(userId, userData) {
    return await this.request(`/users/${userId}`, {
      method: 'PUT',
      body: userData,
    });
  }

  /**
   * Delete a user (admin only)
   * @param {string} userId - User ID to delete
   * @returns {Promise<Object>} - Deletion response
   */
  async deleteUser(userId) {
    return await this.request(`/users/${userId}`, {
      method: 'DELETE',
    });
  }

  /**
   * Check API health
   * @returns {Promise<Object>} - Health status
   */
  async checkHealth() {
    return await this.request('/health');
  }
}

// Export a singleton instance
export default new ApiClient();