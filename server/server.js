const express = require("express");
const mongoose = require("mongoose");
require("dotenv").config();

const authRoutes = require("./routes/authRoutes");

const app = express();

app.use(express.json());

mongoose.connect(process.env.MONGO_URI)
.then(() => console.log("MongoDB Connected"))
.catch((err) => console.log(err));

app.use("/api/auth", authRoutes);

app.get("/", (req, res) => {
    res.send("Blog API Running");
});

app.listen(process.env.PORT || 5000, () => {
    console.log("Server Started");
});