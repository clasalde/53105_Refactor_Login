import { Router } from "express";
import UserModel from "../models/user.model.js";

const router = Router();

router.post("/", async (req, res) => {
    const { first_name, last_name, email, password, age } = req.body;

    try {
        const userExist = await UserModel.findOne({ email: email });
        if (userExist) {
            return res.status(400).send("Email already registered");
        }
        const newUser = await UserModel.create({ first_name, last_name, email, password, age });

        req.session.login = true;
        req.session.user = { ...newUser._doc }
        res.redirect("/products");
    } catch (error) {
        res.status(500).send("Internal Server Error")
    }
})

router.post("/login", async (req, res) => {
    const { email, password } = req.body;

    try {
        const user = await UserModel.findOne({ email: email });
        if (user) {
            if (user.password === password) {
                req.session.login = true;
                req.session.user = {
                    email: user.email,
                    age: user.age,
                    first_name: user.first_name,
                    last_name: user.last_name
                }
                res.redirect("/products");
            } else {
                res.status(401).send("Invalid Password, please retry");
            }
        } else {
            res.status(404).send("User not found");
        }
    } catch (error) {
        res.status(500).send("Internal Server Error")
    }
});

router.get("/logout", (req, res) => {
    if (req.session.login) {
        req.session.destroy();
    }
    res.redirect("/login");
})

export default router; 