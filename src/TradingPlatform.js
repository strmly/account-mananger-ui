import React, { useState, useEffect } from 'react';
import { Plus, Edit, Trash2, Eye, EyeOff, DollarSign, TrendingUp, Users, Settings, LogOut, User, Shield, Key, Monitor, AlertCircle, CheckCircle, Wifi, WifiOff, X, AlertTriangle, Info, Menu } from 'lucide-react';

/**
 * API Client for MT5 Trading Platform
 * Handles all API calls to the backend server
 */
const API_BASE_URL = 'http://localhost:5000/api';

class ApiClient {
  constructor() {
    this.sessionId = null;
  }

  setSessionId(sessionId) {
    this.sessionId = sessionId;
  }

  getSessionId() {
    return this.sessionId;
  }

  clearSession() {
    this.sessionId = null;
  }

  /**
   * Make an HTTP request to the API
   * @param {string} endpoint - API endpoint
   * @param {Object} options - Request options
   * @returns {Promise<any>} - Response data
   */
  async request(endpoint, options = {}) {
    const url = `${API_BASE_URL}${endpoint}`;
    
    const config = {
      headers: {
        'Content-Type': 'application/json',
        ...(this.sessionId && { 'Authorization': `Bearer ${this.sessionId}` }),
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
        throw new Error(data.error || `HTTP ${response.status}: ${response.statusText}`);
      }

      return data;
    } catch (error) {
      console.error(`API Error (${endpoint}):`, error);
      if (error.name === 'TypeError' && error.message.includes('fetch')) {
        throw new Error('Unable to connect to server. Please check if the server is running.');
      }
      throw error;
    }
  }

  // ===== Authentication =====
  async login(credentials) {
    const response = await this.request('/auth/login', {
      method: 'POST',
      body: credentials,
    });
    if (response.session_id) {
      this.setSessionId(response.session_id);
    }
    return response;
  }

  async register(userData) {
    const response = await this.request('/auth/register', {
      method: 'POST',
      body: userData,
    });
    if (response.session_id) {
      this.setSessionId(response.session_id);
    }
    return response;
  }

  async logout() {
    try {
      await this.request('/auth/logout', { method: 'POST' });
    } finally {
      this.clearSession();
    }
  }

  async verifySession() {
    return await this.request('/auth/verify');
  }

  // ===== Account Management =====
  async getAccounts() {
    return await this.request('/accounts');
  }

  async createAccount(accountData) {
    return await this.request('/accounts', {
      method: 'POST',
      body: accountData,
    });
  }

  async updateAccount(accountId, accountData) {
    return await this.request(`/accounts/${accountId}`, {
      method: 'PUT',
      body: accountData,
    });
  }

  async deleteAccount(accountId) {
    return await this.request(`/accounts/${accountId}`, {
      method: 'DELETE',
    });
  }

  // ===== User Management =====
  async getUsers() {
    return await this.request('/users');
  }

  async createUser(userData) {
    return await this.request('/users', {
      method: 'POST',
      body: userData,
    });
  }

  async updateUser(userId, userData) {
    return await this.request(`/users/${userId}`, {
      method: 'PUT',
      body: userData,
    });
  }

  async deleteUser(userId) {
    return await this.request(`/users/${userId}`, {
      method: 'DELETE',
    });
  }

  async checkHealth() {
    return await this.request('/health');
  }
}

// Create singleton instance
const apiClient = new ApiClient();

// Session persistence utilities
const SessionManager = {
  // Try to use cookies for session persistence
  setSession: (sessionData) => {
    try {
      // Set session cookie that expires in 8 hours
      const expires = new Date();
      expires.setTime(expires.getTime() + (8 * 60 * 60 * 1000)); // 8 hours
      document.cookie = `mt5_session=${JSON.stringify(sessionData)}; expires=${expires.toUTCString()}; path=/; SameSite=Strict`;
      return true;
    } catch (error) {
      console.warn('Cookie storage not available:', error);
      return false;
    }
  },

  getSession: () => {
    try {
      const cookies = document.cookie.split(';');
      const sessionCookie = cookies.find(cookie => cookie.trim().startsWith('mt5_session='));
      if (sessionCookie) {
        const sessionData = sessionCookie.split('=')[1];
        return JSON.parse(decodeURIComponent(sessionData));
      }
    } catch (error) {
      console.warn('Failed to retrieve session:', error);
    }
    return null;
  },

  clearSession: () => {
    try {
      document.cookie = 'mt5_session=; expires=Thu, 01 Jan 1970 00:00:00 UTC; path=/;';
    } catch (error) {
      console.warn('Failed to clear session cookie:', error);
    }
  },

  // Fallback: use window.name for basic session persistence
  setFallbackSession: (sessionData) => {
    try {
      window.name = JSON.stringify({ mt5_session: sessionData, timestamp: Date.now() });
      return true;
    } catch (error) {
      console.warn('Window.name storage failed:', error);
      return false;
    }
  },

  getFallbackSession: () => {
    try {
      if (window.name) {
        const data = JSON.parse(window.name);
        // Check if session is less than 8 hours old
        if (data.mt5_session && data.timestamp && (Date.now() - data.timestamp < 8 * 60 * 60 * 1000)) {
          return data.mt5_session;
        }
      }
    } catch (error) {
      console.warn('Failed to retrieve fallback session:', error);
    }
    return null;
  },

  clearFallbackSession: () => {
    try {
      window.name = '';
    } catch (error) {
      console.warn('Failed to clear fallback session:', error);
    }
  }
};

// Notification System Components
const Notification = ({ notification, onClose }) => {
  const { id, type, title, message, duration } = notification;

  useEffect(() => {
    if (duration > 0) {
      const timer = setTimeout(() => {
        onClose(id);
      }, duration);
      return () => clearTimeout(timer);
    }
  }, [id, duration, onClose]);

  const getNotificationStyle = () => {
    switch (type) {
      case 'success':
        return 'bg-green-500/90 border-green-400 text-white';
      case 'error':
        return 'bg-red-500/90 border-red-400 text-white';
      case 'warning':
        return 'bg-yellow-500/90 border-yellow-400 text-white';
      case 'info':
        return 'bg-blue-500/90 border-blue-400 text-white';
      default:
        return 'bg-purple-500/90 border-purple-400 text-white';
    }
  };

  const getIcon = () => {
    switch (type) {
      case 'success':
        return <CheckCircle className="w-4 h-4 sm:w-5 sm:h-5" />;
      case 'error':
        return <AlertCircle className="w-4 h-4 sm:w-5 sm:h-5" />;
      case 'warning':
        return <AlertTriangle className="w-4 h-4 sm:w-5 sm:h-5" />;
      case 'info':
        return <Info className="w-4 h-4 sm:w-5 sm:h-5" />;
      default:
        return <Info className="w-4 h-4 sm:w-5 sm:h-5" />;
    }
  };

  return (
    <div className={`
      ${getNotificationStyle()}
      backdrop-blur-lg border rounded-lg p-3 sm:p-4 shadow-lg transition-all duration-300 transform
      animate-in slide-in-from-right-full
    `}>
      <div className="flex items-start gap-2 sm:gap-3">
        <div className="flex-shrink-0 mt-0.5">
          {getIcon()}
        </div>
        <div className="flex-1 min-w-0">
          {title && (
            <h4 className="text-xs sm:text-sm font-semibold mb-1">{title}</h4>
          )}
          <p className="text-xs sm:text-sm opacity-90">{message}</p>
        </div>
        <button
          onClick={() => onClose(id)}
          className="flex-shrink-0 p-1 rounded-md hover:bg-white/20 transition-colors duration-200 touch-manipulation"
        >
          <X className="w-3 h-3 sm:w-4 sm:h-4" />
        </button>
      </div>
    </div>
  );
};

const NotificationContainer = ({ notifications, onClose }) => {
  if (notifications.length === 0) return null;

  return (
    <div className="fixed top-2 sm:top-4 right-2 sm:right-4 z-50 space-y-2 sm:space-y-3 max-w-[calc(100vw-1rem)] sm:max-w-sm w-full">
      {notifications.map((notification) => (
        <Notification
          key={notification.id}
          notification={notification}
          onClose={onClose}
        />
      ))}
    </div>
  );
};

// Confirmation Dialog Component
const ConfirmDialog = ({ isOpen, onClose, onConfirm, title, message, type = 'warning' }) => {
  if (!isOpen) return null;

  const getButtonStyle = () => {
    switch (type) {
      case 'danger':
        return 'bg-red-500 hover:bg-red-600';
      case 'warning':
        return 'bg-yellow-500 hover:bg-yellow-600';
      default:
        return 'bg-purple-500 hover:bg-purple-600';
    }
  };

  return (
    <div className="fixed inset-0 bg-black/50 backdrop-blur-sm flex items-center justify-center z-50 p-4">
      <div className="bg-white/10 backdrop-blur-lg rounded-xl p-4 sm:p-6 border border-white/20 w-full max-w-sm sm:max-w-md">
        <div className="flex items-center gap-3 mb-4">
          <AlertTriangle className="w-5 h-5 sm:w-6 sm:h-6 text-yellow-400 flex-shrink-0" />
          <h3 className="text-base sm:text-lg font-semibold text-white">{title}</h3>
        </div>
        <p className="text-purple-200 mb-6 text-sm sm:text-base">{message}</p>
        <div className="flex flex-col sm:flex-row gap-3">
          <button
            onClick={onConfirm}
            className={`flex-1 ${getButtonStyle()} text-white py-2 sm:py-2 px-4 rounded-lg font-medium transition-all duration-200 text-sm sm:text-base touch-manipulation`}
          >
            Confirm
          </button>
          <button
            onClick={onClose}
            className="flex-1 bg-white/10 hover:bg-white/20 text-white py-2 sm:py-2 px-4 rounded-lg font-medium transition-all duration-200 border border-white/20 text-sm sm:text-base touch-manipulation"
          >
            Cancel
          </button>
        </div>
      </div>
    </div>
  );
};

// Validation functions moved outside component
const validateEmail = (email) => {
  const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
  return emailRegex.test(email);
};

const validateUsername = (username) => {
  const usernameRegex = /^[a-zA-Z0-9_]{3,20}$/;
  return usernameRegex.test(username);
};

const validatePassword = (password) => {
  return {
    length: password.length >= 8,
    uppercase: /[A-Z]/.test(password),
    lowercase: /[a-z]/.test(password),
    number: /\d/.test(password),
    special: /[!@#$%^&*(),.?":{}|<>]/.test(password)
  };
};

const validateAccountNumber = (accountNumber) => {
  const accountRegex = /^\d{6,12}$/;
  return accountRegex.test(accountNumber);
};

const validateServerName = (server) => {
  return server.length >= 3 && server.length <= 50;
};

const validateName = (name) => {
  const nameRegex = /^[a-zA-Z\s]{2,30}$/;
  return nameRegex.test(name);
};

// Password strength indicator component moved outside
const PasswordStrengthIndicator = ({ password }) => {
  const validation = validatePassword(password);
  const score = Object.values(validation).filter(Boolean).length;
  
  const strengthText = ['Very Weak', 'Weak', 'Fair', 'Good', 'Strong'][score];
  const strengthColor = ['red', 'orange', 'yellow', 'blue', 'green'][score];
  
  return (
    <div className="mt-2">
      <div className="flex gap-1 mb-2">
        {[...Array(5)].map((_, i) => (
          <div
            key={i}
            className={`h-1 flex-1 rounded ${
              i < score ? `bg-${strengthColor}-400` : 'bg-gray-600'
            }`}
          />
        ))}
      </div>
      <div className="text-xs space-y-1">
        <p className={`text-${strengthColor}-400 font-medium`}>
          Password Strength: {strengthText}
        </p>
        <div className="text-purple-300 space-y-0.5">
          <div className={validation.length ? 'text-green-400' : 'text-gray-400'}>
            ✓ At least 8 characters
          </div>
          <div className={validation.uppercase ? 'text-green-400' : 'text-gray-400'}>
            ✓ One uppercase letter
          </div>
          <div className={validation.lowercase ? 'text-green-400' : 'text-gray-400'}>
            ✓ One lowercase letter
          </div>
          <div className={validation.number ? 'text-green-400' : 'text-gray-400'}>
            ✓ One number
          </div>
        </div>
      </div>
    </div>
  );
};

// Input component with validation moved outside
const ValidatedInput = ({ 
  label, 
  type = 'text', 
  value, 
  onChange, 
  error, 
  placeholder, 
  required = false,
  showPasswordStrength = false 
}) => {
  const [showPassword, setShowPassword] = useState(false);
  
  const inputType = type === 'password' && showPassword ? 'text' : type;
  const hasError = !!error;
  const isValid = !hasError && value && value.length > 0;
  
  return (
    <div>
      <label className="block text-purple-200 text-sm font-medium mb-2">
        {label} {required && <span className="text-red-400">*</span>}
      </label>
      <div className="relative">
        <input
          type={inputType}
          value={value}
          onChange={onChange}
          placeholder={placeholder}
          className={`w-full bg-white/10 border rounded-lg px-3 sm:px-4 py-2 sm:py-3 text-white placeholder-purple-300 focus:outline-none focus:ring-2 transition-all duration-200 text-sm sm:text-base ${
            hasError 
              ? 'border-red-500 focus:ring-red-500' 
              : isValid 
              ? 'border-green-500 focus:ring-green-500' 
              : 'border-white/20 focus:ring-purple-500'
          }`}
        />
        
        {type === 'password' && value && (
          <button
            type="button"
            onClick={() => setShowPassword(!showPassword)}
            className="absolute right-3 top-1/2 transform -translate-y-1/2 text-purple-400 hover:text-purple-300 touch-manipulation"
          >
            {showPassword ? <EyeOff className="w-4 h-4" /> : <Eye className="w-4 h-4" />}
          </button>
        )}
        
        {isValid && type !== 'password' && (
          <CheckCircle className="absolute right-3 top-1/2 transform -translate-y-1/2 text-green-400 w-4 h-4" />
        )}
        
        {hasError && (
          <AlertCircle className="absolute right-3 top-1/2 transform -translate-y-1/2 text-red-400 w-4 h-4" />
        )}
      </div>
      
      {showPasswordStrength && type === 'password' && value && (
        <PasswordStrengthIndicator password={value} />
      )}
      
      {error && (
        <p className="mt-1 text-xs sm:text-sm text-red-400 flex items-center gap-1">
          <AlertCircle className="w-3 h-3" />
          {error}
        </p>
      )}
    </div>
  );
};

// Connection status indicator moved outside
const ConnectionIndicator = ({ connectionStatus }) => {
  const getStatusColor = () => {
    switch (connectionStatus) {
      case 'connected': return 'text-green-400';
      case 'disconnected': return 'text-red-400';
      case 'checking': return 'text-yellow-400';
      default: return 'text-gray-400';
    }
  };

  const getStatusIcon = () => {
    switch (connectionStatus) {
      case 'connected': return <Wifi className="w-3 h-3 sm:w-4 sm:h-4" />;
      case 'disconnected': return <WifiOff className="w-3 h-3 sm:w-4 sm:h-4" />;
      default: return <Wifi className="w-3 h-3 sm:w-4 sm:h-4 animate-pulse" />;
    }
  };

  return (
    <div className={`flex items-center gap-1 sm:gap-2 ${getStatusColor()}`}>
      {getStatusIcon()}
      <span className="text-xs sm:text-sm hidden sm:inline">
        {connectionStatus === 'connected' && 'Connected'}
        {connectionStatus === 'disconnected' && 'Server Offline'}
        {connectionStatus === 'checking' && 'Connecting...'}
      </span>
    </div>
  );
};

// Mobile Account Card Component
const AccountCard = ({ account, showPasswords, togglePasswordVisibility, handleEditAccount, handleDeleteAccount, currentUser, getAccountTypeColor, getStatusColor }) => (
  <div className="bg-white/5 rounded-lg p-4 border border-white/10">
    <div className="flex justify-between items-start mb-3">
      <div>
        <h3 className="text-white font-mono text-sm font-medium">{account.account_number}</h3>
        <span className={`inline-block px-2 py-1 rounded-full text-xs font-medium mt-1 ${getAccountTypeColor(account.account_type || 'Forex')}`}>
          {account.account_type || 'Forex'}
        </span>
      </div>
      <span className={`px-2 py-1 rounded-full text-xs font-medium ${getStatusColor(account.status)}`}>
        {account.status}
      </span>
    </div>
    
    <div className="space-y-2 text-sm">
      <div className="flex justify-between">
        <span className="text-purple-200">Server:</span>
        <span className="text-white">{account.server}</span>
      </div>
      <div className="flex justify-between items-center">
        <span className="text-purple-200">Password:</span>
        <div className="flex items-center gap-2">
          <span className="text-white font-mono text-xs">
            {showPasswords[account.id] ? account.password : '••••••••'}
          </span>
          <button
            onClick={() => togglePasswordVisibility(account.id)}
            className="text-purple-400 hover:text-purple-300 touch-manipulation"
          >
            {showPasswords[account.id] ? <EyeOff className="w-3 h-3" /> : <Eye className="w-3 h-3" />}
          </button>
        </div>
      </div>
      <div className="flex justify-between">
        <span className="text-purple-200">Balance:</span>
        <span className="text-white font-mono">${account.balance?.toLocaleString() || '0.00'}</span>
      </div>
      <div className="flex justify-between">
        <span className="text-purple-200">Equity:</span>
        <span className="text-white font-mono">${account.equity?.toLocaleString() || '0.00'}</span>
      </div>
      <div className="flex justify-between">
        <span className="text-purple-200">Created By:</span>
        <span className="text-white">{account.created_by || 'System'}</span>
      </div>
    </div>
    
    {(currentUser.role === 'admin' || currentUser.role === 'manager' || currentUser.role === 'trader') && (
      <div className="flex gap-2 mt-4 pt-3 border-t border-white/10">
        <button
          onClick={() => handleEditAccount(account)}
          className="flex-1 bg-blue-500/20 hover:bg-blue-500/30 text-blue-400 py-2 px-3 rounded-lg font-medium transition-all duration-200 flex items-center justify-center gap-2 text-sm touch-manipulation"
        >
          <Edit className="w-3 h-3" />
          Edit
        </button>
        <button
          onClick={() => handleDeleteAccount(account.id)}
          className="flex-1 bg-red-500/20 hover:bg-red-500/30 text-red-400 py-2 px-3 rounded-lg font-medium transition-all duration-200 flex items-center justify-center gap-2 text-sm touch-manipulation"
        >
          <Trash2 className="w-3 h-3" />
          Delete
        </button>
      </div>
    )}
  </div>
);

// Mobile User Card Component
const UserCard = ({ user, handleEditUser, handleDeleteUser, toggleUserStatus, currentUser, getRoleColor, getStatusColor }) => (
  <div className="bg-white/5 rounded-lg p-4 border border-white/10">
    <div className="flex justify-between items-start mb-3">
      <div>
        <h3 className="text-white font-medium text-sm">{user.firstName} {user.lastName}</h3>
        <p className="text-purple-200 text-xs">@{user.username}</p>
        <p className="text-purple-300 text-xs mt-1">{user.email}</p>
      </div>
      <span className={`px-2 py-1 rounded-full text-xs font-medium ${getRoleColor(user.role)}`}>
        {user.role}
      </span>
    </div>
    
    <div className="flex justify-between items-center mb-3">
      <span className="text-purple-200 text-sm">Status:</span>
      <button
        onClick={() => toggleUserStatus(user.id)}
        className={`px-2 py-1 rounded-full text-xs font-medium transition-all duration-200 ${getStatusColor(user.status)} touch-manipulation`}
      >
        {user.status}
      </button>
    </div>
    
    <div className="flex justify-between mb-4">
      <span className="text-purple-200 text-sm">Last Login:</span>
      <span className="text-white text-sm">
        {user.last_login ? new Date(user.last_login).toLocaleDateString() : 'Never'}
      </span>
    </div>
    
    <div className="flex gap-2 pt-3 border-t border-white/10">
      <button
        onClick={() => handleEditUser(user)}
        className="flex-1 bg-blue-500/20 hover:bg-blue-500/30 text-blue-400 py-2 px-3 rounded-lg font-medium transition-all duration-200 flex items-center justify-center gap-2 text-sm touch-manipulation"
      >
        <Edit className="w-3 h-3" />
        Edit
      </button>
      {user.id !== currentUser.id && (
        <button
          onClick={() => handleDeleteUser(user.id)}
          className="flex-1 bg-red-500/20 hover:bg-red-500/30 text-red-400 py-2 px-3 rounded-lg font-medium transition-all duration-200 flex items-center justify-center gap-2 text-sm touch-manipulation"
        >
          <Trash2 className="w-3 h-3" />
          Delete
        </button>
      )}
    </div>
  </div>
);

const TradingPlatform = () => {
  const [currentUser, setCurrentUser] = useState(null);
  const [authMode, setAuthMode] = useState('login');
  const [accounts, setAccounts] = useState([]);
  const [users, setUsers] = useState([]);
  const [showAddForm, setShowAddForm] = useState(false);
  const [showUserManagement, setShowUserManagement] = useState(false);
  const [editingAccount, setEditingAccount] = useState(null);
  const [editingUser, setEditingUser] = useState(null);
  const [showPasswords, setShowPasswords] = useState({});
  const [isSubmitting, setIsSubmitting] = useState(false);
  const [isLoading, setIsLoading] = useState(true);
  const [connectionStatus, setConnectionStatus] = useState('checking');
  const [sessionId, setSessionId] = useState(null);
  const [mobileMenuOpen, setMobileMenuOpen] = useState(false);
  const [sessionWarningShown, setSessionWarningShown] = useState(false);

  // Session activity tracking
  useEffect(() => {
    if (!currentUser) return;

    // Track user activity to extend session
    const activityEvents = ['mousedown', 'mousemove', 'keypress', 'scroll', 'touchstart', 'click'];
    
    const updateActivity = () => {
      if (currentUser && sessionId) {
        // Update session timestamp in storage
        const sessionData = SessionManager.getSession() || SessionManager.getFallbackSession();
        if (sessionData) {
          sessionData.lastActivity = Date.now();
          if (!SessionManager.setSession(sessionData)) {
            SessionManager.setFallbackSession(sessionData);
          }
        }
      }
    };

    // Add activity listeners
    activityEvents.forEach(event => {
      document.addEventListener(event, updateActivity, true);
    });

    // Session timeout check (every 5 minutes)
    const sessionCheck = setInterval(() => {
      if (!currentUser) return;

      const sessionData = SessionManager.getSession() || SessionManager.getFallbackSession();
      if (sessionData && sessionData.lastActivity) {
        const timeSinceActivity = Date.now() - sessionData.lastActivity;
        const sevenHours = 7 * 60 * 60 * 1000; // 7 hours
        const sessionAge = Date.now() - sessionData.loginTime;

        // Warn at 7 hours, logout at 8 hours
        if (sessionAge > sevenHours && !sessionWarningShown) {
          setSessionWarningShown(true);
          showWarning('Your session will expire in 1 hour due to inactivity. Please save your work.', 'Session Warning');
        }

        // Auto-logout after 8 hours
        if (sessionAge > 8 * 60 * 60 * 1000) {
          handleLogout();
          showError('Your session has expired due to inactivity. Please log in again.', 'Session Expired');
        }
      }
    }, 5 * 60 * 1000); // Check every 5 minutes

    return () => {
      // Cleanup activity listeners
      activityEvents.forEach(event => {
        document.removeEventListener(event, updateActivity, true);
      });
      clearInterval(sessionCheck);
    };
  }, [currentUser, sessionId, sessionWarningShown]);

  // Notification system state
  const [notifications, setNotifications] = useState([]);
  const [confirmDialog, setConfirmDialog] = useState({
    isOpen: false,
    title: '',
    message: '',
    onConfirm: null,
    type: 'warning'
  });
  
  // Form data states
  const [authData, setAuthData] = useState({
    username: '',
    email: '',
    password: '',
    confirmPassword: '',
    firstName: '',
    lastName: ''
  });
  const [accountFormData, setAccountFormData] = useState({
    account_number: '',
    password: '',
    server: '',
    account_type: 'Forex'
  });
  const [userFormData, setUserFormData] = useState({
    username: '',
    email: '',
    firstName: '',
    lastName: '',
    role: 'trader',
    password: ''
  });

  // Validation error states
  const [authErrors, setAuthErrors] = useState({});
  const [accountErrors, setAccountErrors] = useState({});
  const [userErrors, setUserErrors] = useState({});

  // Notification functions
  const showNotification = (type, message, title = '', duration = 5000) => {
    const id = Date.now() + Math.random();
    const notification = {
      id,
      type,
      title,
      message,
      duration
    };
    
    setNotifications(prev => [...prev, notification]);
    
    // Auto-remove after duration
    if (duration > 0) {
      setTimeout(() => {
        removeNotification(id);
      }, duration);
    }
  };

  const removeNotification = (id) => {
    setNotifications(prev => prev.filter(notification => notification.id !== id));
  };

  const showSuccess = (message, title = 'Success') => {
    showNotification('success', message, title);
  };

  const showError = (message, title = 'Error') => {
    showNotification('error', message, title);
  };

  const showWarning = (message, title = 'Warning') => {
    showNotification('warning', message, title);
  };

  const showInfo = (message, title = 'Info') => {
    showNotification('info', message, title);
  };

  const showConfirm = (title, message, onConfirm, type = 'warning') => {
    setConfirmDialog({
      isOpen: true,
      title,
      message,
      onConfirm,
      type
    });
  };

  const closeConfirm = () => {
    setConfirmDialog({
      isOpen: false,
      title: '',
      message: '',
      onConfirm: null,
      type: 'warning'
    });
  };

  // Real-time validation for auth form
  const validateAuthField = (field, value, allData = authData) => {
    const errors = {};

    switch (field) {
      case 'username':
        if (!value) {
          errors.username = 'Username is required';
        } else if (!validateUsername(value)) {
          errors.username = 'Username must be 3-20 characters, letters, numbers, and underscores only';
        }
        break;

      case 'email':
        if (authMode === 'register') {
          if (!value) {
            errors.email = 'Email is required';
          } else if (!validateEmail(value)) {
            errors.email = 'Please enter a valid email address';
          }
        }
        break;

      case 'firstName':
        if (authMode === 'register') {
          if (!value) {
            errors.firstName = 'First name is required';
          } else if (!validateName(value)) {
            errors.firstName = 'First name must be 2-30 characters, letters only';
          }
        }
        break;

      case 'lastName':
        if (authMode === 'register') {
          if (!value) {
            errors.lastName = 'Last name is required';
          } else if (!validateName(value)) {
            errors.lastName = 'Last name must be 2-30 characters, letters only';
          }
        }
        break;

      case 'password':
        if (!value) {
          errors.password = 'Password is required';
        } else if (authMode === 'register') {
          const passwordValidation = validatePassword(value);
          if (!passwordValidation.length) {
            errors.password = 'Password must be at least 8 characters';
          } else if (!passwordValidation.uppercase || !passwordValidation.lowercase || !passwordValidation.number) {
            errors.password = 'Password must contain uppercase, lowercase, and number';
          }
        }
        break;

      case 'confirmPassword':
        if (authMode === 'register') {
          if (!value) {
            errors.confirmPassword = 'Please confirm your password';
          } else if (value !== allData.password) {
            errors.confirmPassword = 'Passwords do not match';
          }
        }
        break;
    }

    return errors;
  };

  // Real-time validation for account form
  const validateAccountField = (field, value) => {
    const errors = {};

    switch (field) {
      case 'account_number':
        if (!value) {
          errors.account_number = 'Account number is required';
        } else if (!validateAccountNumber(value)) {
          errors.account_number = 'Account number must be 6-12 digits';
        } else if (accounts.some(acc => acc.account_number === value && (!editingAccount || editingAccount.account_number !== value))) {
          errors.account_number = 'Account number already exists';
        }
        break;

      case 'password':
        if (!value) {
          errors.password = 'Password is required';
        } else if (value.length < 6) {
          errors.password = 'Password must be at least 6 characters';
        }
        break;

      case 'server':
        if (!value) {
          errors.server = 'Server is required';
        } else if (!validateServerName(value)) {
          errors.server = 'Server name must be 3-50 characters';
        }
        break;
    }

    return errors;
  };

  // Real-time validation for user form
  const validateUserField = (field, value) => {
    const errors = {};

    switch (field) {
      case 'username':
        if (!value) {
          errors.username = 'Username is required';
        } else if (!validateUsername(value)) {
          errors.username = 'Username must be 3-20 characters, letters, numbers, and underscores only';
        } else if (users.some(u => u.username === value && (!editingUser?.id || editingUser.username !== value))) {
          errors.username = 'Username already exists';
        }
        break;

      case 'email':
        if (!value) {
          errors.email = 'Email is required';
        } else if (!validateEmail(value)) {
          errors.email = 'Please enter a valid email address';
        } else if (users.some(u => u.email === value && (!editingUser?.id || editingUser.email !== value))) {
          errors.email = 'Email already exists';
        }
        break;

      case 'firstName':
        if (!value) {
          errors.firstName = 'First name is required';
        } else if (!validateName(value)) {
          errors.firstName = 'First name must be 2-30 characters, letters only';
        }
        break;

      case 'lastName':
        if (!value) {
          errors.lastName = 'Last name is required';
        } else if (!validateName(value)) {
          errors.lastName = 'Last name must be 2-30 characters, letters only';
        }
        break;

      case 'password':
        if (!editingUser?.id && !value) {
          errors.password = 'Password is required for new users';
        } else if (value && value.length < 6) {
          errors.password = 'Password must be at least 6 characters';
        }
        break;
    }

    return errors;
  };

  // Handle auth data changes with validation
  const handleAuthDataChange = (field, value) => {
    const newData = { ...authData, [field]: value };
    setAuthData(newData);
    
    const fieldErrors = validateAuthField(field, value, newData);
    setAuthErrors(prev => ({ ...prev, ...fieldErrors }));
    
    // Clear error if field becomes valid
    if (Object.keys(fieldErrors).length === 0 && authErrors[field]) {
      setAuthErrors(prev => {
        const newErrors = { ...prev };
        delete newErrors[field];
        return newErrors;
      });
    }
  };

  // Handle account data changes with validation
  const handleAccountDataChange = (field, value) => {
    setAccountFormData(prev => ({ ...prev, [field]: value }));
    
    const fieldErrors = validateAccountField(field, value);
    setAccountErrors(prev => ({ ...prev, ...fieldErrors }));
    
    if (Object.keys(fieldErrors).length === 0 && accountErrors[field]) {
      setAccountErrors(prev => {
        const newErrors = { ...prev };
        delete newErrors[field];
        return newErrors;
      });
    }
  };

  // Handle user data changes with validation
  const handleUserDataChange = (field, value) => {
    setUserFormData(prev => ({ ...prev, [field]: value }));
    
    const fieldErrors = validateUserField(field, value);
    setUserErrors(prev => ({ ...prev, ...fieldErrors }));
    
    if (Object.keys(fieldErrors).length === 0 && userErrors[field]) {
      setUserErrors(prev => {
        const newErrors = { ...prev };
        delete newErrors[field];
        return newErrors;
      });
    }
  };

  // Validate entire form
  const validateAuthForm = () => {
    const errors = {};
    
    ['username', 'password'].forEach(field => {
      const fieldErrors = validateAuthField(field, authData[field], authData);
      Object.assign(errors, fieldErrors);
    });

    if (authMode === 'register') {
      ['email', 'firstName', 'lastName', 'confirmPassword'].forEach(field => {
        const fieldErrors = validateAuthField(field, authData[field], authData);
        Object.assign(errors, fieldErrors);
      });
    }

    setAuthErrors(errors);
    return Object.keys(errors).length === 0;
  };

  const validateAccountForm = () => {
    const errors = {};
    
    ['account_number', 'password', 'server'].forEach(field => {
      const fieldErrors = validateAccountField(field, accountFormData[field]);
      Object.assign(errors, fieldErrors);
    });

    setAccountErrors(errors);
    return Object.keys(errors).length === 0;
  };

  const validateUserForm = () => {
    const errors = {};
    
    ['username', 'email', 'firstName', 'lastName', 'password'].forEach(field => {
      const fieldErrors = validateUserField(field, userFormData[field]);
      Object.assign(errors, fieldErrors);
    });

    setUserErrors(errors);
    return Object.keys(errors).length === 0;
  };

  // API call helpers with error handling
  const withErrorHandling = async (apiCall, errorMessage = 'Operation failed') => {
    try {
      return await apiCall();
    } catch (error) {
      console.error('API Error:', error);
      showError(error.message || errorMessage);
      
      // If it's an auth error, logout and clear session
      if (error.message?.includes('401') || error.message?.includes('Unauthorized')) {
        // Clear session data without showing logout message (already showing error)
        setCurrentUser(null);
        setSessionId(null);
        setAccounts([]);
        setUsers([]);
        setShowUserManagement(false);
        setMobileMenuOpen(false);
        
        // Clear stored session data
        SessionManager.clearSession();
        SessionManager.clearFallbackSession();
        apiClient.clearSession();
        
        showWarning('Your session has expired. Please log in again.', 'Session Expired');
      }
      
      throw error;
    }
  };

  useEffect(() => {
    initializeApp();
  }, []);

  useEffect(() => {
    if (currentUser) {
      loadAccounts();
      if (currentUser.role === 'admin' || currentUser.role === 'trader') {
        loadUsers();
      }
    }
  }, [currentUser]);

  useEffect(() => {
    apiClient.setSessionId(sessionId);
  }, [sessionId]);

  const initializeApp = async () => {
    setIsLoading(true);
    setConnectionStatus('checking');
    
    try {
      // Check server health
      await apiClient.checkHealth();
      setConnectionStatus('connected');
      
      // Try to restore session from cookies or fallback storage
      const savedSession = SessionManager.getSession() || SessionManager.getFallbackSession();
      if (savedSession && savedSession.sessionId && savedSession.user) {
        try {
          // Set the session ID for API calls
          apiClient.setSessionId(savedSession.sessionId);
          
          // Verify the session is still valid
          const response = await apiClient.verifySession();
          
          // If verification succeeds, restore the user session
          setCurrentUser(savedSession.user);
          setSessionId(savedSession.sessionId);
          showInfo('Welcome back! Your session has been restored.', 'Session Restored');
          
        } catch (sessionError) {
          console.warn('Saved session is invalid:', sessionError);
          // Clear invalid session data
          SessionManager.clearSession();
          SessionManager.clearFallbackSession();
          apiClient.clearSession();
          showWarning('Your previous session has expired. Please log in again.', 'Session Expired');
        }
      }
      
    } catch (error) {
      console.error('Failed to connect to server:', error);
      setConnectionStatus('disconnected');
    } finally {
      setIsLoading(false);
    }
  };

  const loadUsers = async () => {
    await withErrorHandling(async () => {
      const usersData = await apiClient.getUsers();
      setUsers(usersData.users || usersData);
    }, 'Failed to load users');
  };

  const loadAccounts = async () => {
    await withErrorHandling(async () => {
      const accountsData = await apiClient.getAccounts();
      setAccounts(accountsData.accounts || accountsData);
    }, 'Failed to load accounts');
  };

  const handleAuth = async () => {
    if (!validateAuthForm()) {
      return;
    }

    setIsSubmitting(true);
    try {
      if (authMode === 'register') {
        const response = await apiClient.register({
          username: authData.username,
          email: authData.email,
          firstName: authData.firstName,
          lastName: authData.lastName,
          password: authData.password
        });

        setCurrentUser(response.user);
        setSessionId(response.session_id);
        
        // Save session for persistence across page reloads
        const sessionData = {
          user: response.user,
          sessionId: response.session_id,
          loginTime: Date.now()
        };
        
        // Try cookies first, fallback to window.name
        if (!SessionManager.setSession(sessionData)) {
          SessionManager.setFallbackSession(sessionData);
        }
        
        showSuccess('Account created successfully! Welcome to MT5 Trading Platform.', 'Registration Complete');
        
      } else {
        const response = await apiClient.login({
          username: authData.username,
          password: authData.password
        });

        setCurrentUser(response.user);
        setSessionId(response.session_id);
        
        // Save session for persistence across page reloads
        const sessionData = {
          user: response.user,
          sessionId: response.session_id,
          loginTime: Date.now()
        };
        
        // Try cookies first, fallback to window.name
        if (!SessionManager.setSession(sessionData)) {
          SessionManager.setFallbackSession(sessionData);
        }
        
        showSuccess(`Welcome back, ${response.user.firstName}!`, 'Login Successful');
      }

      setAuthData({ username: '', email: '', password: '', confirmPassword: '', firstName: '', lastName: '' });
      setAuthErrors({});
      
    } catch (error) {
      showError(error.message || 'Authentication failed', 'Login Failed');
    } finally {
      setIsSubmitting(false);
    }
  };

  const handleLogout = async () => {
    try {
      await apiClient.logout();
      showInfo('You have been logged out successfully.', 'Logged Out');
    } catch (error) {
      console.error('Logout error:', error);
    } finally {
      // Clear all session data
      setCurrentUser(null);
      setSessionId(null);
      setAccounts([]);
      setUsers([]);
      setShowUserManagement(false);
      setMobileMenuOpen(false);
      
      // Clear stored session data
      SessionManager.clearSession();
      SessionManager.clearFallbackSession();
      apiClient.clearSession();
    }
  };

  const handleAccountSubmit = async () => {
    if (!validateAccountForm()) {
      return;
    }
    
    setIsSubmitting(true);
    try {
      if (editingAccount) {
        const response = await apiClient.updateAccount(editingAccount.id, {
          ...accountFormData,
          updated_by: currentUser.username
        });
        
        const updatedAccount = response.account || response;
        const updatedAccounts = accounts.map(acc => 
          acc.id === editingAccount.id ? updatedAccount : acc
        );
        setAccounts(updatedAccounts);
        setEditingAccount(null);
        showSuccess(`Account ${accountFormData.account_number} has been updated successfully.`, 'Account Updated');
      } else {
        const response = await apiClient.createAccount({
          ...accountFormData,
          created_by: currentUser.username
        });
        
        const newAccount = response.account || response;
        setAccounts([...accounts, newAccount]);
        showSuccess(`Trading account ${accountFormData.account_number} has been added successfully.`, 'Account Created');
      }
      
      resetAccountForm();
    } catch (error) {
      showError(error.message || 'Failed to save account', 'Account Error');
    } finally {
      setIsSubmitting(false);
    }
  };

  const handleUserSubmit = async () => {
    if (!validateUserForm()) {
      return;
    }

    setIsSubmitting(true);
    try {
      if (editingUser.id) {
        const response = await apiClient.updateUser(editingUser.id, userFormData);
        const updatedUser = response.user || response;
        const updatedUsers = users.map(user => 
          user.id === editingUser.id ? updatedUser : user
        );
        setUsers(updatedUsers);
        showSuccess(`User ${userFormData.username} has been updated successfully.`, 'User Updated');
      } else {
        const response = await apiClient.createUser(userFormData);
        const newUser = response.user || response;
        setUsers([...users, newUser]);
        showSuccess(`User ${userFormData.username} has been created successfully.`, 'User Created');
      }
      
      resetUserForm();
    } catch (error) {
      showError(error.message || 'Failed to save user', 'User Error');
    } finally {
      setIsSubmitting(false);
    }
  };

  const handleEditAccount = (account) => {
    setEditingAccount(account);
    setAccountFormData({
      account_number: account.account_number,
      password: account.password,
      server: account.server,
      account_type: account.account_type || 'Forex'
    });
    setAccountErrors({});
    setShowAddForm(true);
  };

  const handleEditUser = (user) => {
    setEditingUser(user);
    setUserFormData({
      username: user.username,
      email: user.email,
      firstName: user.firstName,
      lastName: user.lastName,
      role: user.role,
      password: ''
    });
    setUserErrors({});
  };

  const handleDeleteAccount = (accountId) => {
    const account = accounts.find(acc => acc.id === accountId);
    showConfirm(
      'Delete Trading Account',
      `Are you sure you want to delete account ${account?.account_number}? This action cannot be undone.`,
      async () => {
        try {
          await apiClient.deleteAccount(accountId);
          const updatedAccounts = accounts.filter(acc => acc.id !== accountId);
          setAccounts(updatedAccounts);
          showSuccess(`Trading account ${account?.account_number} has been deleted.`, 'Account Deleted');
        } catch (error) {
          showError(error.message || 'Failed to delete account', 'Delete Failed');
        }
        closeConfirm();
      },
      'danger'
    );
  };

  const handleDeleteUser = (userId) => {
    if (userId === currentUser.id) {
      showWarning("You cannot delete your own account.", 'Action Not Allowed');
      return;
    }
    
    const user = users.find(u => u.id === userId);
    showConfirm(
      'Delete User',
      `Are you sure you want to delete user ${user?.username}? This action cannot be undone.`,
      async () => {
        try {
          await apiClient.deleteUser(userId);
          const updatedUsers = users.filter(user => user.id !== userId);
          setUsers(updatedUsers);
          showSuccess(`User ${user?.username} has been deleted.`, 'User Deleted');
        } catch (error) {
          showError(error.message || 'Failed to delete user', 'Delete Failed');
        }
        closeConfirm();
      },
      'danger'
    );
  };

  const toggleUserStatus = async (userId) => {
    try {
      const user = users.find(u => u.id === userId);
      const newStatus = user.status === 'active' ? 'inactive' : 'active';
      
      const response = await apiClient.updateUser(userId, { status: newStatus });
      const updatedUser = response.user || response;
      
      const updatedUsers = users.map(u => 
        u.id === userId ? updatedUser : u
      );
      setUsers(updatedUsers);
      showSuccess(`User ${user.username} status has been changed to ${newStatus}.`, 'Status Updated');
    } catch (error) {
      showError(error.message || 'Failed to update user status', 'Update Failed');
    }
  };

  const resetAccountForm = () => {
    setAccountFormData({ account_number: '', password: '', server: '', account_type: 'Forex' });
    setAccountErrors({});
    setShowAddForm(false);
    setEditingAccount(null);
  };

  const refreshSession = async () => {
    try {
      const response = await apiClient.verifySession();
      if (response) {
        // Update session timestamp
        const sessionData = SessionManager.getSession() || SessionManager.getFallbackSession();
        if (sessionData) {
          sessionData.lastActivity = Date.now();
          sessionData.loginTime = Date.now(); // Reset login time to extend session
          if (!SessionManager.setSession(sessionData)) {
            SessionManager.setFallbackSession(sessionData);
          }
          setSessionWarningShown(false); // Reset warning
          showSuccess('Your session has been refreshed successfully.', 'Session Refreshed');
        }
      }
    } catch (error) {
      showError('Failed to refresh session. Please log in again.', 'Session Refresh Failed');
      handleLogout();
    }
  };

  const resetUserForm = () => {
    setUserFormData({ username: '', email: '', firstName: '', lastName: '', role: 'trader', password: '' });
    setUserErrors({});
    setEditingUser(null);
  };

  const togglePasswordVisibility = (id) => {
    setShowPasswords(prev => ({ ...prev, [id]: !prev[id] }));
  };

  const getStatusColor = (status) => {
    switch (status) {
      case 'active': return 'bg-green-100 text-green-800';
      case 'inactive': return 'bg-gray-100 text-gray-800';
      case 'error': return 'bg-red-100 text-red-800';
      default: return 'bg-gray-100 text-gray-800';
    }
  };

  const getAccountTypeColor = (type) => {
    switch (type) {
      case 'FTMO': return 'bg-orange-100 text-orange-800';
      case 'Forex': return 'bg-blue-100 text-blue-800';
      default: return 'bg-gray-100 text-gray-800';
    }
  };

  const getRoleColor = (role) => {
    switch (role) {
      case 'admin': return 'bg-purple-100 text-purple-800';
      case 'manager': return 'bg-blue-100 text-blue-800';
      case 'trader': return 'bg-green-100 text-green-800';
      case 'viewer': return 'bg-gray-100 text-gray-800';
      default: return 'bg-gray-100 text-gray-800';
    }
  };

  // Loading screen
  if (isLoading) {
    return (
      <div className="min-h-screen bg-gradient-to-br from-slate-900 via-purple-900 to-slate-900 flex items-center justify-center p-4">
        <div className="text-center">
          <Monitor className="w-12 h-12 sm:w-16 sm:h-16 text-purple-400 mx-auto mb-4 animate-pulse" />
          <h1 className="text-xl sm:text-2xl font-bold text-white mb-2">Loading MT5 Platform</h1>
          <p className="text-purple-200 mb-4 text-sm sm:text-base">
            {connectionStatus === 'checking' ? 'Connecting to server...' : 'Restoring your session...'}
          </p>
          <div className="flex justify-center">
            <ConnectionIndicator connectionStatus={connectionStatus} />
          </div>
          {connectionStatus === 'connected' && (
            <p className="text-purple-300 text-xs mt-2">Checking saved session data</p>
          )}
        </div>
      </div>
    );
  }

  // Server disconnected screen
  if (connectionStatus === 'disconnected') {
    return (
      <div className="min-h-screen bg-gradient-to-br from-slate-900 via-purple-900 to-slate-900 flex items-center justify-center p-4">
        <div className="bg-white/10 backdrop-blur-lg rounded-xl p-6 sm:p-8 border border-white/20 w-full max-w-md text-center">
          <WifiOff className="w-12 h-12 sm:w-16 sm:h-16 text-red-400 mx-auto mb-4" />
          <h1 className="text-xl sm:text-2xl font-bold text-white mb-2">Server Unavailable</h1>
          <p className="text-purple-200 mb-4 text-sm sm:text-base">
            Unable to connect to the MT5 Trading Platform server at {API_BASE_URL}
          </p>
          <p className="text-purple-300 text-xs sm:text-sm mb-6">
            Please ensure the backend server is running and try again.
          </p>
          <button
            onClick={initializeApp}
            className="bg-gradient-to-r from-purple-500 to-pink-500 hover:from-purple-600 hover:to-pink-600 text-white px-4 sm:px-6 py-2 sm:py-3 rounded-lg font-medium transition-all duration-200 text-sm sm:text-base touch-manipulation"
          >
            Retry Connection
          </button>
        </div>
      </div>
    );
  }

  // Authentication Screen with proper validation
  if (!currentUser) {
    return (
      <>
        <NotificationContainer notifications={notifications} onClose={removeNotification} />
        <div className="min-h-screen bg-gradient-to-br from-slate-900 via-purple-900 to-slate-900 flex items-center justify-center p-4">
          <div className="bg-white/10 backdrop-blur-lg rounded-xl p-6 sm:p-8 border border-white/20 w-full max-w-md">
            <div className="text-center mb-6 sm:mb-8">
              <Monitor className="w-12 h-12 sm:w-16 sm:h-16 text-purple-400 mx-auto mb-4" />
              <h1 className="text-2xl sm:text-3xl font-bold text-white mb-2">Seefeesaw Capital Platform</h1>
              <p className="text-purple-200 text-sm sm:text-base">Professional trading account management</p>
              <div className="mt-4 flex justify-center">
                <ConnectionIndicator connectionStatus={connectionStatus} />
              </div>
            </div>

            <div className="flex bg-white/10 rounded-lg p-1 mb-6">
              <button
                onClick={() => {
                  setAuthMode('login');
                  setAuthErrors({});
                }}
                className={`flex-1 py-2 px-4 rounded-md font-medium transition-all duration-200 text-sm sm:text-base touch-manipulation ${
                  authMode === 'login' 
                    ? 'bg-purple-500 text-white' 
                    : 'text-purple-200 hover:text-white'
                }`}
              >
                Login
              </button>
              <button
                onClick={() => {
                  setAuthMode('register');
                  setAuthErrors({});
                }}
                className={`flex-1 py-2 px-4 rounded-md font-medium transition-all duration-200 text-sm sm:text-base touch-manipulation ${
                  authMode === 'register' 
                    ? 'bg-purple-500 text-white' 
                    : 'text-purple-200 hover:text-white'
                }`}
              >
                Register
              </button>
            </div>

            <div className="space-y-4">
              <ValidatedInput
                label="Username"
                value={authData.username}
                onChange={(e) => handleAuthDataChange('username', e.target.value)}
                error={authErrors.username}
                placeholder="Enter username"
                required
              />

              {authMode === 'register' && (
                <>
                  <ValidatedInput
                    label="Email"
                    type="email"
                    value={authData.email}
                    onChange={(e) => handleAuthDataChange('email', e.target.value)}
                    error={authErrors.email}
                    placeholder="Enter email address"
                    required
                  />
                  <div className="grid grid-cols-2 gap-3">
                    <ValidatedInput
                      label="First Name"
                      value={authData.firstName}
                      onChange={(e) => handleAuthDataChange('firstName', e.target.value)}
                      error={authErrors.firstName}
                      placeholder="First name"
                      required
                    />
                    <ValidatedInput
                      label="Last Name"
                      value={authData.lastName}
                      onChange={(e) => handleAuthDataChange('lastName', e.target.value)}
                      error={authErrors.lastName}
                      placeholder="Last name"
                      required
                    />
                  </div>
                </>
              )}

              <ValidatedInput
                label="Password"
                type="password"
                value={authData.password}
                onChange={(e) => handleAuthDataChange('password', e.target.value)}
                error={authErrors.password}
                placeholder="Enter password"
                required
                showPasswordStrength={authMode === 'register'}
              />

              {authMode === 'register' && (
                <ValidatedInput
                  label="Confirm Password"
                  type="password"
                  value={authData.confirmPassword}
                  onChange={(e) => handleAuthDataChange('confirmPassword', e.target.value)}
                  error={authErrors.confirmPassword}
                  placeholder="Confirm password"
                  required
                />
              )}

              <button
                onClick={handleAuth}
                disabled={isSubmitting || Object.keys(authErrors).length > 0 || connectionStatus !== 'connected'}
                className={`w-full py-2 sm:py-3 rounded-lg font-medium transition-all duration-200 text-sm sm:text-base touch-manipulation ${
                  isSubmitting || Object.keys(authErrors).length > 0 || connectionStatus !== 'connected'
                    ? 'bg-gray-500 cursor-not-allowed'
                    : 'bg-gradient-to-r from-purple-500 to-pink-500 hover:from-purple-600 hover:to-pink-600'
                } text-white`}
              >
                {isSubmitting ? 'Processing...' : (authMode === 'login' ? 'Sign In' : 'Create Account')}
              </button>
            </div>
          </div>
        </div>
      </>
    );
  }

  const totalBalance = accounts.reduce((sum, acc) => sum + (acc.balance || 0), 0);
  const totalEquity = accounts.reduce((sum, acc) => sum + (acc.equity || 0), 0);
  const activeAccounts = accounts.filter(acc => acc.status === 'active').length;
  const activeUsers = users.filter(user => user.status === 'active').length;
  const ftmoAccounts = accounts.filter(acc => acc.account_type === 'FTMO').length;
  const forexAccounts = accounts.filter(acc => acc.account_type === 'Forex').length;

  return (
    <>
      <NotificationContainer notifications={notifications} onClose={removeNotification} />
      <ConfirmDialog 
        isOpen={confirmDialog.isOpen}
        onClose={closeConfirm}
        onConfirm={confirmDialog.onConfirm}
        title={confirmDialog.title}
        message={confirmDialog.message}
        type={confirmDialog.type}
      />
      
      <div className="min-h-screen bg-gradient-to-br from-slate-900 via-purple-900 to-slate-900">
        <div className="container mx-auto px-4 sm:px-6 py-4 sm:py-8">
          {/* Mobile Header */}
          <div className="flex flex-col sm:flex-row justify-between items-start sm:items-center mb-6 sm:mb-8 gap-4">
            <div className="flex-1">
              <h1 className="text-2xl sm:text-4xl font-bold text-white mb-1 sm:mb-2">Seefeesaw Capital Dashboard</h1>
              <p className="text-purple-200 text-sm sm:text-base">Welcome back, {currentUser.firstName} {currentUser.lastName}</p>
            </div>
            
            {/* Desktop Header Controls */}
            <div className="hidden sm:flex items-center gap-4">
              <ConnectionIndicator connectionStatus={connectionStatus} />
              <div className="flex items-center gap-3 bg-white/10 rounded-lg px-4 py-2">
                <User className="w-5 h-5 text-purple-400" />
                <span className="text-white font-medium">{currentUser.username}</span>
                <span className={`px-2 py-1 rounded-full text-xs font-medium ${getRoleColor(currentUser.role)}`}>
                  {currentUser.role}
                </span>
                {/* Session indicator */}
                <div className="w-2 h-2 bg-green-400 rounded-full animate-pulse" title="Session Active"></div>
              </div>
              <button
                onClick={refreshSession}
                className="bg-green-500 hover:bg-green-600 text-white px-4 py-2 rounded-lg font-medium transition-all duration-200 flex items-center gap-2 touch-manipulation"
                title="Refresh your session to extend login time"
              >
                <CheckCircle className="w-4 h-4" />
                Refresh
              </button>
              {(currentUser.role === 'admin' || currentUser.role === 'trader') && (
                <button
                  onClick={() => setShowUserManagement(!showUserManagement)}
                  className="bg-blue-500 hover:bg-blue-600 text-white px-4 py-2 rounded-lg font-medium transition-all duration-200 flex items-center gap-2 touch-manipulation"
                >
                  <Shield className="w-4 h-4" />
                  Users
                </button>
              )}
              <button
                onClick={handleLogout}
                className="bg-red-500 hover:bg-red-600 text-white px-4 py-2 rounded-lg font-medium transition-all duration-200 flex items-center gap-2 touch-manipulation"
              >
                <LogOut className="w-4 h-4" />
                Logout
              </button>
            </div>

            {/* Mobile Header Controls */}
            <div className="flex sm:hidden items-center justify-between w-full">
              <div className="flex items-center gap-2">
                <ConnectionIndicator connectionStatus={connectionStatus} />
                <div className="flex items-center gap-2 bg-white/10 rounded-lg px-3 py-1">
                  <User className="w-4 h-4 text-purple-400" />
                  <span className="text-white font-medium text-sm">{currentUser.username}</span>
                  <span className={`px-2 py-1 rounded-full text-xs font-medium ${getRoleColor(currentUser.role)}`}>
                    {currentUser.role}
                  </span>
                  {/* Session indicator */}
                  <div className="w-1.5 h-1.5 bg-green-400 rounded-full animate-pulse" title="Session Active"></div>
                </div>
              </div>
              <button
                onClick={() => setMobileMenuOpen(!mobileMenuOpen)}
                className="bg-white/10 hover:bg-white/20 text-white p-2 rounded-lg transition-all duration-200 touch-manipulation"
              >
                <Menu className="w-5 h-5" />
              </button>
            </div>

            {/* Mobile Menu */}
            {mobileMenuOpen && (
              <div className="absolute top-20 right-4 z-40 bg-white/10 backdrop-blur-lg rounded-xl border border-white/20 p-4 min-w-48 sm:hidden">
                <div className="space-y-3">
                  <button
                    onClick={() => {
                      refreshSession();
                      setMobileMenuOpen(false);
                    }}
                    className="w-full bg-green-500 hover:bg-green-600 text-white px-4 py-2 rounded-lg font-medium transition-all duration-200 flex items-center gap-2 text-sm touch-manipulation"
                  >
                    <CheckCircle className="w-4 h-4" />
                    Refresh Session
                  </button>
                  {(currentUser.role === 'admin' || currentUser.role === 'trader') && (
                    <button
                      onClick={() => {
                        setShowUserManagement(!showUserManagement);
                        setMobileMenuOpen(false);
                      }}
                      className="w-full bg-blue-500 hover:bg-blue-600 text-white px-4 py-2 rounded-lg font-medium transition-all duration-200 flex items-center gap-2 text-sm touch-manipulation"
                    >
                      <Shield className="w-4 h-4" />
                      User Management
                    </button>
                  )}
                  <button
                    onClick={() => {
                      handleLogout();
                      setMobileMenuOpen(false);
                    }}
                    className="w-full bg-red-500 hover:bg-red-600 text-white px-4 py-2 rounded-lg font-medium transition-all duration-200 flex items-center gap-2 text-sm touch-manipulation"
                  >
                    <LogOut className="w-4 h-4" />
                    Logout
                  </button>
                </div>
              </div>
            )}
          </div>

          {/* Stats Cards */}
          <div className="grid grid-cols-2 lg:grid-cols-4 gap-3 sm:gap-6 mb-6 sm:mb-8">
            <div className="bg-white/10 backdrop-blur-lg rounded-xl p-4 sm:p-6 border border-white/20">
              <div className="flex items-center justify-between">
                <div>
                  <p className="text-purple-200 text-xs sm:text-sm font-medium">Total Balance</p>
                  <p className="text-lg sm:text-2xl font-bold text-white">${totalBalance.toLocaleString()}</p>
                </div>
                <DollarSign className="w-6 h-6 sm:w-8 sm:h-8 text-green-400" />
              </div>
            </div>
            
            <div className="bg-white/10 backdrop-blur-lg rounded-xl p-4 sm:p-6 border border-white/20">
              <div className="flex items-center justify-between">
                <div>
                  <p className="text-purple-200 text-xs sm:text-sm font-medium">Total Equity</p>
                  <p className="text-lg sm:text-2xl font-bold text-white">${totalEquity.toLocaleString()}</p>
                </div>
                <TrendingUp className="w-6 h-6 sm:w-8 sm:h-8 text-blue-400" />
              </div>
            </div>
            
            <div className="bg-white/10 backdrop-blur-lg rounded-xl p-4 sm:p-6 border border-white/20">
              <div className="flex items-center justify-between">
                <div>
                  <p className="text-purple-200 text-xs sm:text-sm font-medium">Active Accounts</p>
                  <p className="text-lg sm:text-2xl font-bold text-white">{activeAccounts} / {accounts.length}</p>
                  <div className="flex flex-col sm:flex-row gap-1 sm:gap-3 mt-2">
                    <span className="text-xs bg-orange-100 text-orange-800 px-2 py-1 rounded-full">
                      FTMO: {ftmoAccounts}
                    </span>
                    <span className="text-xs bg-blue-100 text-blue-800 px-2 py-1 rounded-full">
                      Forex: {forexAccounts}
                    </span>
                  </div>
                </div>
                <Monitor className="w-6 h-6 sm:w-8 sm:h-8 text-purple-400" />
              </div>
            </div>

            {(currentUser.role === 'admin' || currentUser.role === 'trader') && (
              <div className="bg-white/10 backdrop-blur-lg rounded-xl p-4 sm:p-6 border border-white/20">
                <div className="flex items-center justify-between">
                  <div>
                    <p className="text-purple-200 text-xs sm:text-sm font-medium">Active Users</p>
                    <p className="text-lg sm:text-2xl font-bold text-white">{activeUsers} / {users.length}</p>
                  </div>
                  <Users className="w-6 h-6 sm:w-8 sm:h-8 text-orange-400" />
                </div>
              </div>
            )}
          </div>

          {/* User Management Section (Admin Only) */}
          {(currentUser.role === 'admin' || currentUser.role === 'trader') && showUserManagement && (
            <div className="bg-white/10 backdrop-blur-lg rounded-xl border border-white/20 overflow-hidden mb-6 sm:mb-8">
              <div className="px-4 sm:px-6 py-4 border-b border-white/20 flex flex-col sm:flex-row justify-between items-start sm:items-center gap-4">
                <h2 className="text-lg sm:text-xl font-semibold text-white flex items-center gap-2">
                  <Shield className="w-5 h-5" />
                  User Management
                </h2>
                <button
                  onClick={() => setEditingUser({})}
                  className="bg-gradient-to-r from-blue-500 to-purple-500 hover:from-blue-600 hover:to-purple-600 text-white px-4 py-2 rounded-lg font-medium transition-all duration-200 flex items-center gap-2 text-sm touch-manipulation"
                >
                  <Plus className="w-4 h-4" />
                  Add User
                </button>
              </div>
              
              {/* Desktop Table */}
              <div className="hidden lg:block overflow-x-auto">
                <table className="w-full">
                  <thead className="bg-white/5">
                    <tr>
                      <th className="px-6 py-4 text-left text-purple-200 font-medium">User</th>
                      <th className="px-6 py-4 text-left text-purple-200 font-medium">Email</th>
                      <th className="px-6 py-4 text-left text-purple-200 font-medium">Role</th>
                      <th className="px-6 py-4 text-left text-purple-200 font-medium">Status</th>
                      <th className="px-6 py-4 text-left text-purple-200 font-medium">Last Login</th>
                      <th className="px-6 py-4 text-left text-purple-200 font-medium">Actions</th>
                    </tr>
                  </thead>
                  <tbody>
                    {users.map((user) => (
                      <tr key={user.id} className="border-b border-white/10 hover:bg-white/5">
                        <td className="px-6 py-4">
                          <div className="text-white font-medium">{user.firstName} {user.lastName}</div>
                          <div className="text-purple-200 text-sm">@{user.username}</div>
                        </td>
                        <td className="px-6 py-4 text-purple-200">{user.email}</td>
                        <td className="px-6 py-4">
                          <span className={`px-3 py-1 rounded-full text-xs font-medium ${getRoleColor(user.role)}`}>
                            {user.role}
                          </span>
                        </td>
                        <td className="px-6 py-4">
                          <button
                            onClick={() => toggleUserStatus(user.id)}
                            className={`px-3 py-1 rounded-full text-xs font-medium transition-all duration-200 ${getStatusColor(user.status)} touch-manipulation`}
                          >
                            {user.status}
                          </button>
                        </td>
                        <td className="px-6 py-4 text-purple-200 text-sm">
                          {user.last_login ? new Date(user.last_login).toLocaleDateString() : 'Never'}
                        </td>
                        <td className="px-6 py-4">
                          <div className="flex gap-2">
                            <button
                              onClick={() => handleEditUser(user)}
                              className="text-blue-400 hover:text-blue-300 p-2 rounded-lg hover:bg-white/10 transition-all duration-200 touch-manipulation"
                            >
                              <Edit className="w-4 h-4" />
                            </button>
                            {user.id !== currentUser.id && (
                              <button
                                onClick={() => handleDeleteUser(user.id)}
                                className="text-red-400 hover:text-red-300 p-2 rounded-lg hover:bg-white/10 transition-all duration-200 touch-manipulation"
                              >
                                <Trash2 className="w-4 h-4" />
                              </button>
                            )}
                          </div>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>

              {/* Mobile Cards */}
              <div className="lg:hidden p-4 space-y-4">
                {users.map((user) => (
                  <UserCard
                    key={user.id}
                    user={user}
                    handleEditUser={handleEditUser}
                    handleDeleteUser={handleDeleteUser}
                    toggleUserStatus={toggleUserStatus}
                    currentUser={currentUser}
                    getRoleColor={getRoleColor}
                    getStatusColor={getStatusColor}
                  />
                ))}
              </div>
            </div>
          )}

          {/* Add Account Button */}
          {(currentUser.role === 'admin' || currentUser.role === 'manager' || currentUser.role === 'trader') && (
            <div className="mb-6">
              <button
                onClick={() => setShowAddForm(true)}
                className="bg-gradient-to-r from-purple-500 to-pink-500 hover:from-purple-600 hover:to-pink-600 text-white px-4 sm:px-6 py-2 sm:py-3 rounded-lg font-medium transition-all duration-200 flex items-center gap-2 shadow-lg hover:shadow-xl text-sm sm:text-base touch-manipulation"
              >
                <Plus className="w-4 h-4 sm:w-5 sm:h-5" />
                Add Trading Account
              </button>
            </div>
          )}

          {/* Account Form Modal with Validation */}
          {showAddForm && (
            <div className="fixed inset-0 bg-black/50 backdrop-blur-sm flex items-center justify-center z-50 p-4">
              <div className="bg-white/10 backdrop-blur-lg rounded-xl p-6 sm:p-8 border border-white/20 w-full max-w-md">
                <h2 className="text-xl sm:text-2xl font-bold text-white mb-6">
                  {editingAccount ? 'Edit Account' : 'Add New Account'}
                </h2>
                
                <div className="space-y-4">
                  <ValidatedInput
                    label="Account Number"
                    value={accountFormData.account_number}
                    onChange={(e) => handleAccountDataChange('account_number', e.target.value)}
                    error={accountErrors.account_number}
                    placeholder="Enter 6-12 digit account number"
                    required
                  />
                  
                  <ValidatedInput
                    label="Password"
                    type="password"
                    value={accountFormData.password}
                    onChange={(e) => handleAccountDataChange('password', e.target.value)}
                    error={accountErrors.password}
                    placeholder="Enter account password"
                    required
                  />
                  
                  <ValidatedInput
                    label="Server"
                    value={accountFormData.server}
                    onChange={(e) => handleAccountDataChange('server', e.target.value)}
                    error={accountErrors.server}
                    placeholder="e.g., XMGlobal-MT5 2"
                    required
                  />
                  
                  <div>
                    <label className="block text-purple-200 text-sm font-medium mb-2">
                      Account Type <span className="text-red-400">*</span>
                    </label>
                    <select
                      value={accountFormData.account_type}
                      onChange={(e) => handleAccountDataChange('account_type', e.target.value)}
                      className="w-full bg-white/10 border border-white/20 rounded-lg px-3 sm:px-4 py-2 sm:py-3 text-white focus:outline-none focus:ring-2 focus:ring-purple-500 text-sm sm:text-base"
                    >
                      <option value="FTMO" className="bg-gray-800">FTMO Account</option>
                      <option value="Nasdaq" className="bg-gray-800">Nasdaq Account</option>
                      <option value="S&P500" className="bg-gray-800">S&P500 Account</option>
                      <option value="Forex" className="bg-gray-800">Forex Account</option>
                      <option value="Forex" className="bg-gray-800">XM Account</option>
                    </select>
                  </div>
                  
                  <div className="flex flex-col sm:flex-row gap-3 pt-4">
                    <button
                      onClick={handleAccountSubmit}
                      disabled={isSubmitting || Object.keys(accountErrors).length > 0}
                      className={`flex-1 py-2 sm:py-3 rounded-lg font-medium transition-all duration-200 text-sm sm:text-base touch-manipulation ${
                        isSubmitting || Object.keys(accountErrors).length > 0
                          ? 'bg-gray-500 cursor-not-allowed'
                          : 'bg-gradient-to-r from-purple-500 to-pink-500 hover:from-purple-600 hover:to-pink-600'
                      } text-white`}
                    >
                      {isSubmitting ? 'Saving...' : (editingAccount ? 'Update Account' : 'Add Account')}
                    </button>
                    <button
                      onClick={resetAccountForm}
                      className="flex-1 bg-white/10 hover:bg-white/20 text-white py-2 sm:py-3 rounded-lg font-medium transition-all duration-200 border border-white/20 text-sm sm:text-base touch-manipulation"
                    >
                      Cancel
                    </button>
                  </div>
                </div>
              </div>
            </div>
          )}

          {/* User Form Modal with Validation */}
          {editingUser && (
            <div className="fixed inset-0 bg-black/50 backdrop-blur-sm flex items-center justify-center z-50 p-4">
              <div className="bg-white/10 backdrop-blur-lg rounded-xl p-6 sm:p-8 border border-white/20 w-full max-w-md">
                <h2 className="text-xl sm:text-2xl font-bold text-white mb-6">
                  {editingUser.id ? 'Edit User' : 'Add New User'}
                </h2>
                
                <div className="space-y-4">
                  <div className="grid grid-cols-2 gap-3">
                    <ValidatedInput
                      label="First Name"
                      value={userFormData.firstName}
                      onChange={(e) => handleUserDataChange('firstName', e.target.value)}
                      error={userErrors.firstName}
                      placeholder="First name"
                      required
                    />
                    <ValidatedInput
                      label="Last Name"
                      value={userFormData.lastName}
                      onChange={(e) => handleUserDataChange('lastName', e.target.value)}
                      error={userErrors.lastName}
                      placeholder="Last name"
                      required
                    />
                  </div>
                  
                  <ValidatedInput
                    label="Username"
                    value={userFormData.username}
                    onChange={(e) => handleUserDataChange('username', e.target.value)}
                    error={userErrors.username}
                    placeholder="Enter username"
                    required
                  />
                  
                  <ValidatedInput
                    label="Email"
                    type="email"
                    value={userFormData.email}
                    onChange={(e) => handleUserDataChange('email', e.target.value)}
                    error={userErrors.email}
                    placeholder="Enter email address"
                    required
                  />
                  
                  <div>
                    <label className="block text-purple-200 text-sm font-medium mb-2">
                      Role <span className="text-red-400">*</span>
                    </label>
                    <select
                      value={userFormData.role}
                      onChange={(e) => handleUserDataChange('role', e.target.value)}
                      className="w-full bg-white/10 border border-white/20 rounded-lg px-3 sm:px-4 py-2 sm:py-3 text-white focus:outline-none focus:ring-2 focus:ring-purple-500 text-sm sm:text-base"
                    >
                      <option value="viewer" className="bg-gray-800">Viewer</option>
                      <option value="trader" className="bg-gray-800">Trader</option>
                      <option value="manager" className="bg-gray-800">Manager</option>
                      <option value="admin" className="bg-gray-800">Admin</option>
                    </select>
                  </div>
                  
                  <ValidatedInput
                    label={editingUser.id ? "New Password (optional)" : "Password"}
                    type="password"
                    value={userFormData.password}
                    onChange={(e) => handleUserDataChange('password', e.target.value)}
                    error={userErrors.password}
                    placeholder={editingUser.id ? "Leave empty to keep current password" : "Enter password"}
                    required={!editingUser.id}
                  />
                  
                  <div className="flex flex-col sm:flex-row gap-3 pt-4">
                    <button
                      onClick={handleUserSubmit}
                      disabled={isSubmitting || Object.keys(userErrors).length > 0}
                      className={`flex-1 py-2 sm:py-3 rounded-lg font-medium transition-all duration-200 text-sm sm:text-base touch-manipulation ${
                        isSubmitting || Object.keys(userErrors).length > 0
                          ? 'bg-gray-500 cursor-not-allowed'
                          : 'bg-gradient-to-r from-blue-500 to-purple-500 hover:from-blue-600 hover:to-purple-600'
                      } text-white`}
                    >
                      {isSubmitting ? 'Saving...' : (editingUser.id ? 'Update User' : 'Add User')}
                    </button>
                    <button
                      onClick={resetUserForm}
                      className="flex-1 bg-white/10 hover:bg-white/20 text-white py-2 sm:py-3 rounded-lg font-medium transition-all duration-200 border border-white/20 text-sm sm:text-base touch-manipulation"
                    >
                      Cancel
                    </button>
                  </div>
                </div>
              </div>
            </div>
          )}

          {/* Accounts Section */}
          <div className="bg-white/10 backdrop-blur-lg rounded-xl border border-white/20 overflow-hidden">
            <div className="px-4 sm:px-6 py-4 border-b border-white/20">
              <h2 className="text-lg sm:text-xl font-semibold text-white flex items-center gap-2">
                <Settings className="w-5 h-5" />
                Trading Accounts
              </h2>
            </div>
            
            {/* Desktop Table */}
            <div className="hidden lg:block overflow-x-auto">
              <table className="w-full">
                <thead className="bg-white/5">
                  <tr>
                    <th className="px-6 py-4 text-left text-purple-200 font-medium">Account Number</th>
                    <th className="px-6 py-4 text-left text-purple-200 font-medium">Server</th>
                    <th className="px-6 py-4 text-left text-purple-200 font-medium">Type</th>
                    <th className="px-6 py-4 text-left text-purple-200 font-medium">Password</th>
                    <th className="px-6 py-4 text-left text-purple-200 font-medium">Status</th>
                    <th className="px-6 py-4 text-left text-purple-200 font-medium">Balance</th>
                    <th className="px-6 py-4 text-left text-purple-200 font-medium">Equity</th>
                    <th className="px-6 py-4 text-left text-purple-200 font-medium">Created By</th>
                    {(currentUser.role === 'admin' || currentUser.role === 'manager' || currentUser.role === 'trader') && (
                      <th className="px-6 py-4 text-left text-purple-200 font-medium">Actions</th>
                    )}
                  </tr>
                </thead>
                <tbody>
                  {accounts.map((account) => (
                    <tr key={account.id} className="border-b border-white/10 hover:bg-white/5">
                      <td className="px-6 py-4 text-white font-mono">{account.account_number}</td>
                      <td className="px-6 py-4 text-purple-200">{account.server}</td>
                      <td className="px-6 py-4">
                        <span className={`px-3 py-1 rounded-full text-xs font-medium ${getAccountTypeColor(account.account_type || 'Forex')}`}>
                          {account.account_type || 'Forex'}
                        </span>
                      </td>
                      <td className="px-6 py-4">
                        <div className="flex items-center gap-2">
                          <span className="text-white font-mono">
                            {showPasswords[account.id] ? account.password : '••••••••'}
                          </span>
                          <button
                            onClick={() => togglePasswordVisibility(account.id)}
                            className="text-purple-400 hover:text-purple-300 touch-manipulation"
                          >
                            {showPasswords[account.id] ? <EyeOff className="w-4 h-4" /> : <Eye className="w-4 h-4" />}
                          </button>
                        </div>
                      </td>
                      <td className="px-6 py-4">
                        <span className={`px-3 py-1 rounded-full text-xs font-medium ${getStatusColor(account.status)}`}>
                          {account.status}
                        </span>
                      </td>
                      <td className="px-6 py-4 text-white font-mono">${account.balance?.toLocaleString() || '0.00'}</td>
                      <td className="px-6 py-4 text-white font-mono">${account.equity?.toLocaleString() || '0.00'}</td>
                      <td className="px-6 py-4 text-purple-200">{account.created_by || 'System'}</td>
                      {(currentUser.role === 'admin' || currentUser.role === 'manager' || currentUser.role === 'trader') && (
                        <td className="px-6 py-4">
                          <div className="flex gap-2">
                            <button
                              onClick={() => handleEditAccount(account)}
                              className="text-blue-400 hover:text-blue-300 p-2 rounded-lg hover:bg-white/10 transition-all duration-200 touch-manipulation"
                            >
                              <Edit className="w-4 h-4" />
                            </button>
                            <button
                              onClick={() => handleDeleteAccount(account.id)}
                              className="text-red-400 hover:text-red-300 p-2 rounded-lg hover:bg-white/10 transition-all duration-200 touch-manipulation"
                            >
                              <Trash2 className="w-4 h-4" />
                            </button>
                          </div>
                        </td>
                      )}
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>

            {/* Mobile Cards */}
            <div className="lg:hidden p-4 space-y-4">
              {accounts.map((account) => (
                <AccountCard
                  key={account.id}
                  account={account}
                  showPasswords={showPasswords}
                  togglePasswordVisibility={togglePasswordVisibility}
                  handleEditAccount={handleEditAccount}
                  handleDeleteAccount={handleDeleteAccount}
                  currentUser={currentUser}
                  getAccountTypeColor={getAccountTypeColor}
                  getStatusColor={getStatusColor}
                />
              ))}
            </div>
            
            {accounts.length === 0 && (
              <div className="text-center py-8 sm:py-12 px-4">
                <Monitor className="w-12 h-12 sm:w-16 sm:h-16 text-purple-400 mx-auto mb-4" />
                <p className="text-purple-200 text-base sm:text-lg">No trading accounts configured</p>
                <p className="text-purple-300 text-sm">Add your first MT5 trading account to get started</p>
              </div>
            )}
          </div>
        </div>
      </div>
    </>
  );
};

export default TradingPlatform;