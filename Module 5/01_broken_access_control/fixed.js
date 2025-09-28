// Require authentication middleware
function authenticateUser(req, res, next) {
  if (!req.user) return res.status(401).json({ error: 'Unauthenticated' });
  next();
}

app.get('/profile/:userId', authenticateUser, (req, res) => {
  // Enforce ownership
  if (String(req.user.id) !== String(req.params.userId)) {
    return res.status(403).json({ error: 'Forbidden' });
  }

  User.findById(req.params.userId, (err, user) => {
    if (err) return res.status(500).send(err);
    if (!user) return res.status(404).json({ error: 'User not found' });
    res.json(user);
  });
});
