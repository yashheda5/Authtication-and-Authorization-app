const bcrypt = require('bcrypt');
const User=require("../models/user")
const jwt=require("jsonwebtoken");
require("dotenv").config();
exports.signup =async(req,res)=>{
    try{
        const {name,email,password,role}=req.body;
        const existingUser=await User.findOne({email});

        if(existingUser){
            return res.status(400).json({
                success:false,
                message:"User aldready exists"
            });
        }
        let hashedPassword ;
        try{
            hashedPassword=await bcrypt.hash(password,12);
        }catch(err){
            return res.status(500).json({
                success:false,
                message:"error in hashing password"
            })
        }

        const user = await User.create({
            name,email,password:hashedPassword,role
        })

        return res.status(200).json({
            success:true,
            message:"user created successfully"
        });


    }catch(err){
        console.log(error);
        return res.status(500).json({
            success:false,
            message:"user could not be registered try later"
        })

    }
}
exports.login =async(req,res)=>{
    try{
        const {email,password}=req.body;
        if(!email || !password){
            return res.status(400).json({
                success:false,
                message:"Please provide both email and password"
            })
        }
        const user = await User.findOne({email});
        if(!user){
            return res.status(401).json({
                success:false,
                message:"Invalid email address or user not registered"
            })
        }
        const payload={
            email: user.email,
            id:user._id,
            role:user.role,
        }
        if(await bcrypt.compare(password,user.password)){
            let token=jwt.sign(payload,process.env.JWT_SECRET,{
                expiresIn:"2h",
            });
            user.token=token; 
            user.password=undefined;
            const options={
                expiresIn: new Date(Date.now() + 3*24*60*60*1000),
                httpOnly:true
            }
            res.cookie("token",token,options).status(200).json({
                success:true,
                token,
                user,
                message:"user logged in sucessfully"
            })


        }else{
            return res.status(403).json({
                success:false,
                message:"Invalid password"
            })
        }
    } catch(error){
        console.log(error);
        return res.status(500).json({
            success:false,
            message:"Login failure"
        })
    }
}