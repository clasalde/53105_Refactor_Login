import express from "express";
import exphbs from "express-handlebars";
import productsRouter from "./routes/products.router.js";
import cartsRouter from "./routes/carts.router.js";
import viewsRouter from "./routes/views.router.js";
import sessionsRouter from "./routes/sessions.router.js";
import multer from "multer";
import session from "express-session";
import MongoStore from "connect-mongo";
import "./database.js";

const app = express();
const PUERTO = 8080;

//Middlewares
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.static("./src/public"));

app.use(session({
    secret:"secretCoder",
    resave: true,
    saveUninitialized: true,
    store: MongoStore.create({
        mongoUrl:"mongodb+srv://calasalde:desafio@cluster0.obskgp2.mongodb.net/ecommerce?retryWrites=true&w=majority&appName=Cluster0", ttl: 500
    })
}));


//Handlebars Config
app.engine("handlebars", exphbs.engine());
app.set("view engine", "handlebars");
app.set("views", "./src/views");

//Routes
app.use("/api/products", productsRouter);
app.use("/api/carts", cartsRouter);
app.use("/api/sessions", sessionsRouter);
app.use("/", viewsRouter);

//Upload images with multer
const storage = multer.diskStorage({
    destination: (req, file, cb) => {
        cb(null, "./src/public/img");
    },
    filename: (req, file, cb) => {
        cb(null, file.originalname);
    }
});
const upload = multer({ storage: storage });
app.post("/upload", upload.array("kamado"), (req, res) => {
    res.send("Image uploaded!");
});

//Server Port
app.listen(PUERTO, () => {
    console.log(`Server running on port: ${PUERTO}`);
});