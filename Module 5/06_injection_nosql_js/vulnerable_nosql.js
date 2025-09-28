// vulnerable_nosql.js
app.get('/user', (req, res) => {
  // trusts query params directly -> operator injection possible
  db.collection('users').findOne({ username: req.query.username }, (err, user) => {
    if (err) throw err;
    res.json(user);
  });
});
