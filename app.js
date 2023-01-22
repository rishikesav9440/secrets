//jshint esversion:6
const express = require("express")
const ejs = require("ejs")
const bodyParser = require("body-parser")
const mongoose = require("mongoose")
mongoose.set("strictQuery",false);
const session = require('express-session')
const passport = require("passport")
const port = process.env.PORT || 3000;
const passportLocalMongoose = require("passport-local-mongoose")
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const findOrCreate = require('mongoose-find-or-create')


require('dotenv').config()

var encrypt = require('mongoose-encryption');
const app = express();

app.set('view engine','ejs');
app.use(express.static("public"));
app.use(bodyParser.urlencoded({extended:true}));

app.use(session({
    secret: 'keyboard cat',
    resave: false,
    saveUninitialized: false,
  }))
  app.use(passport.initialize());
  app.use(passport.session());


  mongoose.connect("mongodb+srv://rishi-admin:9440161382@cluster0.shzxbcq.mongodb.net/userDB");


const userSchema = new mongoose.Schema({
    username:String,
    password:String,
    googleId:String,
    secret:String
});
userSchema.plugin(passportLocalMongoose)
userSchema.plugin(findOrCreate)
const User = mongoose.model("User",userSchema);
passport.use(User.createStrategy());

passport.use(new GoogleStrategy({
    clientID:     process.env.CLIENT_ID,
    clientSecret: process.env.CLIENT_SECRET,
    callbackURL: "http://localhost:3000/auth/google/secrets",
    userProfileURL: "https://www.googleapis.com/oauth2/v3/userinfo",
  },
  function(accessToken, refreshToken, profile, cb) {
    User.findOrCreate({ googleId: profile.id }, function (err, user) {
      return cb(err, user);
    });
  }
));
passport.serializeUser(function(user, cb) {
    process.nextTick(function() {
      cb(null, { id: user.id, username: user.username });
    });
  });
  
  passport.deserializeUser(function(user, cb) {
    process.nextTick(function() {
      return cb(null, user);
    });
  });
var secret = process.env.SECRET;
userSchema.plugin(encrypt, { secret: secret , encryptedFields: ['password']});


app.get("/",function(req,res){
    res.render("home")
})
app.get("/login",function(req,res){
    res.render("login")
})
app.get("/register",function(req,res){
    res.render("register")
})
app.get("/secrets",function(req,res){
    User.find({"secret":{$ne:null}},function(err,foundUsersList){
        if(!err){
            if(foundUsersList){
                res.render("secrets",{usersWithSecrets:foundUsersList});
            }
        }
    })
})
app.get("/submit",function(req,res){
    if(req.isAuthenticated()){
        res.render("submit")
    }
    else{
        res.redirect("/login")
    }
})
app.post("/submit",function(req,res){
    const submittedSecret = req.body.secret

    User.findById(req.user.id,function(err,foundUser){
        if(!err){
            if(foundUser){
                foundUser.secret = submittedSecret
                foundUser.save(function(err){
                    if(!err){
                        res.redirect("/secrets")
                    }
                    else{
                        console.log(err);
                    }
                })
            }
        }
        else{
            console.log(err);
        }
    })
})
app.get('/logout', function (req, res, next) {
    req.session.user = null
    req.session.save(function (err) {
      if (err) next(err)
      req.session.regenerate(function (err) {
        if (err) next(err)
        res.redirect('/')
      })
    })
  })
  
app.get('/auth/google',
passport.authenticate('google', { scope: ['profile'] }));

app.get('/auth/google/secrets', 
  passport.authenticate('google', { failureRedirect: '/login' }),
  function(req, res) {
    res.redirect('/secrets');
  });

  app.post('/login', passport.authenticate('local', { failureRedirect: '/' }),  function(req, res) {
	res.redirect('/secrets');
});

app.post("/register",function(req,res){
    User.register({username:req.body.username},req.body.password,function(err,user){
        if(err){
            console.log(err);
            res.redirect("/register")
        }
        else{
            passport.authenticate("local")(req,res,function(){
                res.redirect("/secrets")
            })
            
        }
    })

});
app.listen(port,function(){
    console.log("Started");
})