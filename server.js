const express = require('express');
const path = require('path');
const bcrypt = require('bcrypt');

const app = express();
const PORT = 3000;

app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.static(path.join(__dirname, 'public')));

// In-memory storage: users reset when the server restarts.
let users = [];
let nextId = 1;

const VALID_ROLES = ['admin', 'staff', 'user'];

// Remove passwords and password hashes from API responses.
function sanitizeUser(user) {
  if (!user) return null;

  return {
    id: user.id,
    name: user.name,
    email: user.email,
    role: user.role
  };
}

function validEmail(email) {
  return typeof email === 'string' &&
    /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email.trim());
}

function findUserById(id) {
  const numericId = Number(id);

  if (!Number.isInteger(numericId) || numericId < 1) {
    return undefined;
  }

  return users.find(user => user.id === numericId);
}

function emailTaken(email, excludeId = null) {
  const normalizedEmail = email.trim().toLowerCase();

  return users.some(user =>
    user.email.toLowerCase() === normalizedEmail &&
    user.id !== excludeId
  );
}

// Home page
app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'login.html'));
});

// GET all users
app.get('/api/users', (req, res) => {
  res.json(users.map(sanitizeUser));
});

// CREATE user through the API.
// Accepts admin, staff, or user roles for lab testing.
app.post('/api/users', async (req, res) => {
  try {
    const { name, email, password, role } = req.body || {};

    if (
      typeof name !== 'string' || !name.trim() ||
      !validEmail(email) ||
      typeof password !== 'string' || password.length < 6 ||
      !VALID_ROLES.includes(role)
    ) {
      return res.status(400).json({
        message: 'Provide a valid name, email, password (at least 6 characters), and role (admin, staff, or user).'
      });
    }

    if (emailTaken(email)) {
      return res.status(409).json({
        message: 'Email already exists.'
      });
    }

    const newUser = {
      id: nextId++,
      name: name.trim(),
      email: email.trim().toLowerCase(),
      password: await bcrypt.hash(password, 10),
      role
    };

    users.push(newUser);

    return res.status(201).json({
      message: 'User created successfully.',
      user: sanitizeUser(newUser)
    });
  } catch (error) {
    console.error('Create user error:', error);
    return res.status(500).json({
      message: 'Internal server error.'
    });
  }
});

// GET one user
app.get('/api/users/:id', (req, res) => {
  const user = findUserById(req.params.id);

  if (!user) {
    return res.status(404).json({
      message: 'User not found.'
    });
  }

  return res.json(sanitizeUser(user));
});

// UPDATE user through the API
app.put('/api/users/:id', async (req, res) => {
  try {
    const user = findUserById(req.params.id);

    if (!user) {
      return res.status(404).json({
        message: 'User not found.'
      });
    }

    const { name, email, password, role } = req.body || {};

    if (name !== undefined) {
      if (typeof name !== 'string' || !name.trim()) {
        return res.status(400).json({
          message: 'Name cannot be empty.'
        });
      }

      user.name = name.trim();
    }

    if (email !== undefined) {
      if (!validEmail(email)) {
        return res.status(400).json({
          message: 'Enter a valid email.'
        });
      }

      if (emailTaken(email, user.id)) {
        return res.status(409).json({
          message: 'Email already exists.'
        });
      }

      user.email = email.trim().toLowerCase();
    }

    if (role !== undefined) {
      if (!VALID_ROLES.includes(role)) {
        return res.status(400).json({
          message: 'Role must be admin, staff, or user.'
        });
      }

      user.role = role;
    }

    if (password !== undefined) {
      if (typeof password !== 'string' || password.length < 6) {
        return res.status(400).json({
          message: 'Password must be at least 6 characters.'
        });
      }

      user.password = await bcrypt.hash(password, 10);
    }

    return res.json({
      message: 'User updated successfully.',
      user: sanitizeUser(user)
    });
  } catch (error) {
    console.error('Update user error:', error);
    return res.status(500).json({
      message: 'Internal server error.'
    });
  }
});

// DELETE user
app.delete('/api/users/:id', (req, res) => {
  const user = findUserById(req.params.id);

  if (!user) {
    return res.status(404).json({
      message: 'User not found.'
    });
  }

  users = users.filter(item => item.id !== user.id);

  // Task 5 expects 204 No Content.
  return res.status(204).send();
});

// PUBLIC REGISTRATION: role is always "user".
app.post('/api/register', async (req, res) => {
  try {
    const { name, email, password } = req.body || {};

    if (
      typeof name !== 'string' || !name.trim() ||
      !validEmail(email) ||
      typeof password !== 'string' || password.length < 6
    ) {
      return res.status(400).json({
        message: 'Provide a name, valid email, and password of at least 6 characters.'
      });
    }

    if (emailTaken(email)) {
      return res.status(409).json({
        message: 'Email already exists.'
      });
    }

    const newUser = {
      id: nextId++,
      name: name.trim(),
      email: email.trim().toLowerCase(),
      password: await bcrypt.hash(password, 10),
      role: 'user'
    };

    users.push(newUser);

    return res.status(201).json({
      message: 'Registration successful.',
      user: sanitizeUser(newUser)
    });
  } catch (error) {
    console.error('Registration error:', error);
    return res.status(500).json({
      message: 'Internal server error.'
    });
  }
});

// LOGIN: server decides destination from the stored role.
app.post('/api/login', async (req, res) => {
  try {
    const { email, password } = req.body || {};

    if (
      typeof email !== 'string' || !validEmail(email) ||
      typeof password !== 'string' || !password
    ) {
      return res.status(400).json({
        message: 'Email and password are required.'
      });
    }

    const user = users.find(
      item => item.email === email.trim().toLowerCase()
    );

    if (!user || !(await bcrypt.compare(password, user.password))) {
      return res.status(401).json({
        message: 'Invalid email or password.'
      });
    }

    const redirectMap = {
      admin: '/admin.html',
      staff: '/staff.html',
      user: '/user.html'
    };

    return res.json({
      message: 'Login successful.',
      user: sanitizeUser(user),
      redirectTo: redirectMap[user.role]
    });
  } catch (error) {
    console.error('Login error:', error);
    return res.status(500).json({
      message: 'Internal server error.'
    });
  }
});

// UPDATE PROFILE: verifies current password before changing password.
app.put('/api/profile/:id', async (req, res) => {
  try {
    const user = findUserById(req.params.id);

    if (!user) {
      return res.status(404).json({
        message: 'User not found.'
      });
    }

    const { name, email, currentPassword, newPassword } = req.body || {};

    if (name !== undefined) {
      if (typeof name !== 'string' || !name.trim()) {
        return res.status(400).json({
          message: 'Name cannot be empty.'
        });
      }

      user.name = name.trim();
    }

    if (email !== undefined) {
      if (!validEmail(email)) {
        return res.status(400).json({
          message: 'Enter a valid email.'
        });
      }

      if (emailTaken(email, user.id)) {
        return res.status(409).json({
          message: 'Email already exists.'
        });
      }

      user.email = email.trim().toLowerCase();
    }

    if (newPassword !== undefined && newPassword !== '') {
      if (
        typeof currentPassword !== 'string' ||
        !(await bcrypt.compare(currentPassword, user.password))
      ) {
        return res.status(401).json({
          message: 'Current password is incorrect.'
        });
      }

      if (typeof newPassword !== 'string' || newPassword.length < 6) {
        return res.status(400).json({
          message: 'New password must be at least 6 characters.'
        });
      }

      user.password = await bcrypt.hash(newPassword, 10);
    }

    return res.json({
      message: 'Profile updated successfully.',
      user: sanitizeUser(user)
    });
  } catch (error) {
    console.error('Profile update error:', error);
    return res.status(500).json({
      message: 'Internal server error.'
    });
  }
});

// Handle malformed JSON requests
app.use((err, req, res, next) => {
  if (err instanceof SyntaxError && err.status === 400 && 'body' in err) {
    return res.status(400).json({
      message: 'Invalid JSON request body.'
    });
  }

  console.error('Unexpected server error:', err);

  return res.status(500).json({
    message: 'Internal server error.'
  });
});

app.listen(PORT, () => {
  console.log(`Server running at http://localhost:${PORT}`);
  console.log(`Login URL: http://localhost:${PORT}/login.html`);
  console.log(`Register URL: http://localhost:${PORT}/register.html`);
  console.log(`Users API URL: http://localhost:${PORT}/api/users`);
  console.log('User storage is in memory and resets when the server restarts.');
});