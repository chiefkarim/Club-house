const express = require("express");
const path = require("path");
const session = require("express-session");
const passport = require("passport");
const LocalStrategy = require("passport-local").Strategy;
const mongoose = require("mongoose");
const Schema = mongoose.Schema;
const bcrypt = require("bcryptjs")
require('dotenv').config()

//connecting to database
const mongoDB = process.env.DATABASE_URI
mongoose.connect(mongoDB,{useUnifiedTopology:true,useNewUrlParser:true})
const db = mongoose.connection
db.on("error", console.error.bind(console,"MongoDB connection error:"))

const User = mongoose.model("User",new Schema({
    username: {type:String, required:true},
    password:{type:String, required:true}
}))

const app= express()
app.set("./views",__dirname)
app.set("view engine", "ejs")

app.use(session({secret:"cats",resave:false, saveUninitialized:true}))
app.use(passport.initialize())
app.use(passport.session())
app.use(express.urlencoded({extended:false}))

//setting up authentication
passport.serializeUser(function(user, done) {
    done(null, user.id);
  });

passport.deserializeUser(async function(id, done) {
    try {
      const user = await User.findById(id);
      done(null, user);
    } catch(err) {
      done(err);
    };
  });
passport.use(
    new LocalStrategy(async(username, password, done)=>{
        try{
            const user = await User.findOne({username: username})
            const match = bcrypt.compare(password, user.password)
            if(!user){
                return done(null,false,{message:"Incorrect username"})
            }
            if(!match){
                return done(null,false,{message:"Incorrect password"})
            }
            return done(null,user)
        }catch(err){
            return done(err)
        }
    })
)
//passing current user object
app.use(function(req,res,next){
    res.locals.currentUser = req.user
    next()
})

//Routing
app.get("/",(req,res)=>{
    console.log(req.user)
    res.render("index",{user:req.user})})
app.get("/sign-up",(req,res)=>res.render("sign-up"))
app.post("/sign-up",async(req,res,next)=>{
    bcrypt.hash(req.body.password,10,async(err,hashedPassword)=>{
        if(err){
            console.log(err)
            res.redirect("/")
        }else{

            try{
                const user = new User({
                    username:req.body.username,
                    password:hashedPassword
                })
            
                const result =await user.save()
                console.log(result)
                res.redirect("/")
            } catch(err){
            return next(err)
            }
        }

    })
})
app.get("/sign-in",(req,res)=>res.render('sign-in'))
app.post("/sign-in",
    passport.authenticate("local",{
        successRedirect:"/",
        failureRedirect:"/"
    })
)
app.get("/log-out",(req,res,next)=>{
    req.logout(function(err){
        if(err){
            return next(err)
        }
        res.redirect('/')
    })
})

app.listen(3000, ()=> console.log("app listening on  https://localhost:3000"))