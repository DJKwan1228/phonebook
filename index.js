import express from "express";
import bodyParser from "body-parser";
import pg from "pg";
import bcrypt from "bcrypt";
import passport from "passport";
import { Strategy } from "passport-local";
import session from "express-session";
import env from "dotenv";

const app = express();
const port = 3000;
const saltRounds = 10;
env.config();

app.use(session({
    secret: "PHONEBOOKDETAIL",
    resave: false,
    saveUninitialized: true
  })
);

app.use(bodyParser.urlencoded({ extended: true }));
app.use(express.static("public"));

// https://www.npmjs.com/package/passport
app.use(passport.initialize());
app.use(passport.session());


// initialize db from postgres
const db = new pg.Client({
  user : process.env.ACCESS_USER,
  password : process.env.ACCESS_PASSWORD,
  database : process.env.ACCESS_DATABASE,
  host: process.env.ACCESS_HOST,
  port : process.env.ACCESS_PORT,
});

// connect the db
db.connect();

app.get("/", (req, res) => {
  res.render("home.ejs");
});

app.get("/login", (req, res) => {
  res.render("login.ejs");
});

app.get("/register", (req, res) => {
  res.render("register.ejs");
});

app.get("/phonebook", async (req, res) => {
  console.log(req.user);

  // Get or retrieve registered phonebook data
  if (req.isAuthenticated()) {
    try {
      const result = await db.query(
        `SELECT names, mobile_number, phonebook_email FROM users WHERE username = $1`,
        [req.user.username]
      );
      console.log(result);
      const bookName = result.rows[0].names;
      const mobileNo = result.rows[0].mobile_number;
      const emailAddress = result.rows[0].phonebook_email;
      if (bookName || mobileNo ||emailAddress) {
        res.render("phonebook.ejs", { name: bookName, mobileNumber : mobileNo, email : emailAddress });
      } else {
        res.render("phonebook.ejs", { name: "", mobileNumber : "", email : "" });
      }
    } catch (err) {
      console.log(err);
    }
  } else {
    res.redirect("/login");
  }
});

// create or update registered phonebook data
app.post("/create", async function (req, res) {
  const existingName = req.body.name;
  const existingMobile = req.body.mobileNumber;
  const existingEmail = req.body.phoneEmail;

  console.log(req.user);
  try {
    await db.query(`UPDATE users SET names = $1, mobile_number = $2, phonebook_email = $3 WHERE username = $4`, [
      existingName,
      existingMobile,
      existingEmail,
      req.user.username,
    ]);
    res.redirect("/phonebook");
  } catch (err) {
    console.log(err);
  }
});

// to retrieve name and mobile number using get method
app.get("/create" , (req, res) => {
    if (req.isAuthenticated) {
      res.render("create.ejs");
    } else {
      res.render("/login");
    }

});

app.post(
  "/login",
  passport.authenticate("local", {
    successRedirect: "/phonebook",
    failureRedirect: "/login",
  })
);

app.get("/logout", (req, res) => {
  req.logout((err) => {
    if (err) console.log(err);
    res.redirect("/");
  })
})

app.post("/register", async (req, res) => {
  const username = req.body.username;
  const password = req.body.password;

  try {
    const checkResult = await db.query("SELECT * FROM users WHERE username = $1", [
      username,
    ]);

    if (checkResult.rows.length > 0) {
      res.redirect("/login");
    } else {
      bcrypt.hash(password, saltRounds, async (err, hash) => {
        if (err) {
          console.error("Error hashing password:", err);
        } else {
          const result = await db.query(
            "INSERT INTO users (username, password) VALUES ($1, $2) RETURNING *",
            [username, hash]
          );
          const user = result.rows[0];
          req.login(user, (err) => {
            console.log("success");
            res.redirect("/phonebook");
          });
        }
      });
    }
  } catch (err) {
    console.log(err);
  }
});


passport.use(
  new Strategy(async function verify(username, password, cb) {
    try {
      const result = await db.query("SELECT * FROM users WHERE username = $1 ", [
        username,
      ]);
      if (result.rows.length > 0) {
        const user = result.rows[0];
        const storedHashedPassword = user.password;
        bcrypt.compare(password, storedHashedPassword, (err, valid) => {
          if (err) {
            //Error with password check
            console.error("Error comparing passwords:", err);
            return cb(err);
          } else {
            if (valid) {
              //Passed password check
              return cb(null, user);
            } else {
              //Did not pass password check
              return cb(null, false);
            }
          }
        });
      } else {
        return cb("User not found");
      }
    } catch (err) {
      console.log(err);
    }
  })
);

passport.serializeUser((user, cb) => {
  cb(null, user);
});
passport.deserializeUser((user, cb) => {
  cb(null, user);
});

app.listen(port, () => {
  console.log(`Server running on port ${port}`);
});
