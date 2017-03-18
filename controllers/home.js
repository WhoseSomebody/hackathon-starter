/**
 * GET /
 * Home page.
 */
exports.index = (req, res) => {
  if (req.user)
    res.render('home', {
      title: 'Home'
    });
  else
    return res.redirect('/login')
};
