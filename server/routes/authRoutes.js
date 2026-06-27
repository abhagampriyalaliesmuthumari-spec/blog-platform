const express = require("express");

const router = express.Router();

router.post("/register", (req, res) => {

    const { name, email, password } = req.body;

    res.json({
        message: "User Registered",
        name,
        email
    });

});

router.get("/test", (req, res) => {
    res.send("Auth Route Working");
});

module.exports = router;