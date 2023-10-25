const express = require("express");
const app = express();
const connectDB = require("./Config/db");
const dotenv = require("dotenv");
const cors = require("cors");
const userRoutes = require("./Routes/user");
const courseRoutes = require("./Routes/Course");

dotenv.config();
connectDB();
app.use(express.json());
app.use(cors());


app.get("/", (req, res) => {
  res
    .status(200)
    .json({
      message:
        "Welcome",
    });
});
app.use("/user", userRoutes);
app.use("/course", courseRoutes);

const port = process.env.PORT || 3000;
app.listen(port, () => {
  console.log(`Server is running on port ${port}`);
});
