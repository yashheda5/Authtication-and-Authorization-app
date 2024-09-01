 const express=require("express");
 const app =express();

 require("dotenv").config();

 const PORT=process.env.PORT || 4000;

 app.use(express.json());

 require("./Config/database").connect();

 const user = require("./routes/user")
 app.use("/api/v1",user);
 
 app.listen(PORT,()=>{
    console.log(`server is running on ${PORT}`);
 })
 