const express  = require("express");
const bcrypt   = require("bcrypt");
const sql      = require("sqlite3").verbose();
const cors     = require("cors");
const jwt      = require("jsonwebtoken");

const app = express();

const bodyParser = require("body-parser");
const jsonParser = bodyParser.json();


const db = new sql.Database("./users.db", (err) => {
   if (err) {
      throw err;
   }
   console.log("opening db connection")
   // create table if needed
   let s = `CREATE TABLE IF NOT EXISTS users (
               user_id INTEGER PRIMARY KEY AUTOINCREMENT,
               user_em text NOT NULL UNIQUE,
               user_pw text NOT NULL
            );`;
   db.run(s, [], (err) => {
      if (err) {
         throw err;
      }
   })
});

app.use(cors());

app.post("/login", jsonParser, (req, res) => {
   let user_em = req.body.em;
   let user_pw = req.body.pw;
   let q = `SELECT user_id, user_em, user_pw FROM users WHERE user_em = "${user_em}";`
   // get user from db
   db.get(q, (err, row) => {
      // db error
      if (err) {
         console.log(err.message);
         return res.json({
            msg: "login failed, try again",
            jwt: ""
         })
      }
      // user not in db
      if (!row) {
         return res.json({
            msg: `login failed. no user '${user_em}' in db. try again`,
            jwt: ""
         })
      }
      // bccrypt.compare
      bcrypt.compare(user_pw, row.user_pw, (err, same) => {
         if (err) {
            console.log(err.message);
            return res.json({
               msg: "login failed, try again",
               jwt: ""
            })
         }
         // wrong pw
         if (!same) {
            return res.json({
               msg: "login failed - incorrect password. check for typos and try again",
               jwt: ""
            })
         }
         res.json({
            msg: `logged in as '${row.user_em}'`,
            jwt: jwt.sign({ sub: `${row.user_id}` }, "secret")
         })
      })
   })
})


app.post("/signup", jsonParser, (req, res) => {
   let user_em = req.body.em;
   let user_pw = req.body.pw;
   bcrypt.hash(user_pw, 14, (err, hash_pw) => {
      let q = `INSERT INTO users (user_em, user_pw) VALUES ("${user_em}", "${hash_pw}");`
      db.run(q, (err) => {
         if (err) {
            console.log(err.message);
            return res.json({
               msg: "signup failed, try again",
               jwt: ""
            })
         }
         res.json({
            msg: "signup successful",
            jwt: jwt.sign({ sub: `${this.lastID}` }, "secret")
         })
      })
   })
})

app.listen(3001, () => console.log("Server started on port 3001"));

// process.on("exit", () => {
//    db.close((err) => {
//       if (err) {
//          throw err
//       }
//       console.log("closing db connection")
//    })
// })

