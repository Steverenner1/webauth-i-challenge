// const bcrypt = require('bcryptjs');

// const Users = require('./users-model.js');

module.exports = (req, res, next) => {
    if (req.session && req.session.username) {
        next();
    } else {
        res.status(401).json({ message: "You shall not pass!" });
    }
//   let { username, password } = req.headers;

//   Users.findBy({ username })
//     .first()
//     .then(user => {
//       if (user && bcrypt.compareSync(password, user.password)) {
//         next();
//       } else {
//         res.status(401).json({ message: 'You shall not pass!' });
//       }
//     })
//     .catch(error => {
//       res.status(500).json(error);
//     });
};