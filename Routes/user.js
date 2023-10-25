const express = require('express');
const router = express.Router();
const User = require('../Models/user.model');
const jwt = require("jsonwebtoken");
const bcrypt = require("bcrypt");
const fs=require("fs")
const { OAuth2Client } = require('google-auth-library');

require("dotenv").config();





router.post("/register", async (req, res) => {
  const { name, email, password, gender, age } = req.body;
  try {
    const emailcheck = await User.findOne({ email });
    if (emailcheck) {
      res.status(400).send({ msg: "Email id already used" });
    } else {
      bcrypt.hash(password, 5, async (err, hash) => {
        const user = new User({
          name,
          email,
          password: hash,
        });
        await user.save();
        res.status(200).send({ msg: "User registered successfully" });
      });
    }
  } catch (error) {
    res.status(400).send({ msg: error.message });
  }
});

  router.post("/login", async (req, res) => {
    const { email, password } = req.body;
    try {
      const user = await User.findOne({ email });
      if (user) {
        bcrypt.compare(password, user.password, (err, result) => {
          if (result) {
            const token = jwt.sign({ userId: user._id }, process.env.secret_code); 
            res.status(200).json({
              msg: "User logged in successfully",
      
              token: token,
            });
          } else {
            res.status(400).json({ msg: "Wrong credentials" });
          }
        });
      } else {
        res.status(400).json({ msg: "No user exists" });
      }
    } catch (error) {
      res.status(400).json({ msg: error.message });
    }
  });

router.post( "/google",async (req, res) => {
    const { tokenId } = req.body;
    const client = new OAuth2Client('17936703355-2irj2ekhhi3lagomvp5i13bfvuc8gi1t.apps.googleusercontent.com'); // Replace with your actual client ID
  
    try {
      const response = await client.verifyIdToken({
        idToken: tokenId,
        audience: '17936703355-2irj2ekhhi3lagomvp5i13bfvuc8gi1t.apps.googleusercontent.com', 
      });
      const payload = response.getPayload();
      const email = payload.email;
      const user = await User.findOne({ email });
  
      if (!user) {
        const newUser = new User({ email, googleId: payload.sub });
        await newUser.save();
      }
  
      const token = jwt.sign({ email }, process.env.secret_code, { expiresIn: '1h' });
      res.send({ token });
    } catch (error) {
      console.log(error)
      res.status(401).send('Google authentication failed');
    }
  });


//   router.get("/logout", (req, res) => {
//     try {
//         const token = req.headers.authorization;
//         const blacklisteddata = JSON.parse(fs.readFileSync("./blacklisted.json", "utf-8"));
//         blacklisteddata.push(token)
//         fs.writeFileSync("./blacklisted.json", JSON.stringify(blacklisteddata))
//         res.send("Logout Successfull")
//     } catch (error) {
//         res.send(error)
//     }
// })
module.exports = router;
