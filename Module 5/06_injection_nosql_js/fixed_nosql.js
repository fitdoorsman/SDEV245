/ fixed_nosql.js
const { query, validationResult } = require('express-validator');

app.get(
  '/user',
  // validate/sanitize to plain string
  query('username').isString().trim().isLength({ min: 1, max: 64 })
    .custom(v => {
      if (v.includes('$') || v.includes('{') || v.includes('}')) throw new Error('Invalid characters');
      return true;
    }),
  async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) return res.status(400).json({ errors: errors.array() });

    const username = req.query.username;
    // use explicit equality to avoid operator injection
    const user = await db.collection('users').findOne({ username: { $eq: username } });
    if (!user) return res.status(404).json({ error: 'Not found' });
    res.json(user);
  }
);
